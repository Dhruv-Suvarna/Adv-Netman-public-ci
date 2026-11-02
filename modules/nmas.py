"""Coordinate repository-owned NMAS stages; never contact or configure devices."""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys

BASE = Path(__file__).resolve().parents[1]
MONITORING = BASE / "monitoring"
VENV = Path(os.environ.get("NMAS_VENV", str(BASE.parent / ".venv"))).absolute()


class NmasError(RuntimeError):
    """A mandatory NMAS stage failed."""


def stage(label, command, verbose=False):
    env = dict(os.environ, NMAS_VENV=str(VENV), PIP_DISABLE_PIP_VERSION_CHECK="1")
    try:
        result = subprocess.run(command, cwd=BASE, env=env, text=True, capture_output=True)
    except OSError as exc:
        raise NmasError(f"{label}: {exc}") from exc
    output = result.stdout + result.stderr
    # Never echo generated credentials, even on failure or with --verbose.
    secret_file = MONITORING / "runtime/monitoring.env"
    if secret_file.exists():
        for line in secret_file.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and value and ("PASSWORD" in key or "TOKEN" in key):
                output = output.replace(value, "[REDACTED]")
    print(f"[ NMAS ] {label:.<30} {'PASS' if result.returncode == 0 else 'FAIL'}", flush=True)
    if verbose or result.returncode:
        print(output.rstrip(), flush=True)
    if result.returncode:
        raise NmasError(f"{label} failed (exit {result.returncode}); dependent stages stopped")
    return output


def validate_runtime():
    """Reject unsafe/missing credentials for an initialized installation."""
    env_file = MONITORING / "runtime/monitoring.env"
    if not env_file.exists():
        for name in ("influxdb2", "influxdb2-engine", "grafana"):
            directory = env_file.parent / name
            if directory.exists():
                try:
                    populated = any(directory.iterdir())
                except PermissionError:
                    populated = True
                if populated:
                    raise NmasError("Runtime data exists but monitoring.env is missing; restore its credentials")
        return
    if env_file.is_symlink() or env_file.stat().st_mode & 0o077:
        raise NmasError("monitoring.env must be a regular protected file (mode 600)")
    values = {}
    for line in env_file.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key in values or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise NmasError("monitoring.env requires unique KEY=VALUE entries using letters, digits, underscore, dot or hyphen")
        values[key] = value
    required = {"INFLUXDB_ADMIN_USER", "INFLUXDB_ADMIN_PASSWORD", "INFLUXDB_ORG", "INFLUXDB_BUCKET", "INFLUXDB_TOKEN", "GRAFANA_ADMIN_USER", "GRAFANA_ADMIN_PASSWORD"}
    if not required <= values.keys():
        raise NmasError("monitoring.env is missing mandatory credentials/organization/bucket values")


def validate_inventory(require_address=False):
    import yaml
    inv = yaml.safe_load((BASE / "inventory.yml").read_text())
    mgmt = inv["management"]
    if ipaddress.ip_interface(mgmt["nmas_ipv4"]).ip != ipaddress.ip_address("192.168.200.100"):
        raise NmasError("Inventory NMAS address does not match the committed receiver bindings")
    if not mgmt.get("host_interface"):
        raise NmasError("Inventory management.host_interface is required")
    if require_address:
        import json
        result = subprocess.run(["ip", "-j", "address", "show", "dev", mgmt["host_interface"]], check=True, capture_output=True, text=True)
        if not any(a.get("local") == "192.168.200.100" for link in json.loads(result.stdout) for a in link.get("addr_info", [])):
            raise NmasError("NMAS management address must already exist before receiver provisioning")


def prepare_runtime(verbose=False):
    validate_runtime()
    stage("Host dependencies", ["bash", str(MONITORING / "scripts/bootstrap_nmas.sh")], verbose)
    stage("Python dependencies", ["bash", str(MONITORING / "scripts/install_python_dependencies.sh")], verbose)


def verify_nmas(verbose=False):
    return stage("Verification", ["bash", str(MONITORING / "tests/verify_nmas_infrastructure.sh")], verbose)


def ensure_nmas_infrastructure(verbose=False, prepared=False):
    validate_runtime()
    if not prepared:
        prepare_runtime(verbose)
    validate_inventory(require_address=True)
    for label, script in (("Receivers and logrotate", "install_nmas_receivers.sh"), ("InfluxDB and Grafana", "start_nmas_monitoring.sh")):
        stage(label, ["bash", str(MONITORING / "scripts" / script)], verbose)
    stage("Retention", [str(VENV / "bin/python"), str(MONITORING / "scripts/influxdb_retention.py"), "--apply"], verbose)
    return verify_nmas(verbose)


def entrypoint():
    """Bootstrap before master imports third-party Lab 1 dependencies."""
    parser = argparse.ArgumentParser(description="Lab orchestration with NMAS monitoring provisioning")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--snmp-only", action="store_true", help="Provision and verify SNMP only on the deployed lab")
    modes.add_argument("--syslog-only", action="store_true", help="Provision and verify syslog only on the deployed lab")
    modes.add_argument("--telemetry-only", action="store_true", help="Provision/verify gNMI streaming + NETCONF only on the deployed lab")
    modes.add_argument("--grafana-only", action="store_true", help="Provision/verify Grafana dashboards only; do not configure devices")
    modes.add_argument("--topology-only", action="store_true", help="Provision/verify the NetworkX dynamic topology only; do not configure devices")
    modes.add_argument("--nmas-only", action="store_true", help="Provision/verify NMAS only; do not enter Lab 1 configuration")
    parser.add_argument("--verbose", action="store_true", help="Show NMAS stage output")
    args = parser.parse_args()
    try:
        if os.environ.pop("_NMAS_BOOTSTRAPPED", "") != str(BASE):
            prepare_runtime(args.verbose)
        if Path(sys.prefix) != VENV:
            env = dict(os.environ, _NMAS_BOOTSTRAPPED=str(BASE))
            os.execve(str(VENV / "bin/python"), [str(VENV / "bin/python"), str(BASE / "master.py"), *sys.argv[1:]], env)
        validate_inventory()
        if args.snmp_only:
            from modules.snmp import ensure_snmp_infrastructure
            ensure_snmp_infrastructure(args.verbose)
            raise SystemExit(0)
        if args.syslog_only:
            from modules.syslog import ensure_syslog_infrastructure
            ensure_syslog_infrastructure(args.verbose)
            raise SystemExit(0)
        if args.telemetry_only:
            from modules.telemetry import ensure_telemetry_infrastructure
            ensure_telemetry_infrastructure(args.verbose)
            raise SystemExit(0)
        if args.grafana_only:
            ensure_nmas_infrastructure(args.verbose, prepared=True)
            from modules.grafana import ensure_grafana_infrastructure
            ensure_grafana_infrastructure(args.verbose)
            raise SystemExit(0)
        if args.topology_only:
            ensure_nmas_infrastructure(args.verbose, prepared=True)
            from modules.topology import ensure_topology_infrastructure
            ensure_topology_infrastructure(args.verbose)
            raise SystemExit(0)
        if args.nmas_only:
            ensure_nmas_infrastructure(args.verbose, prepared=True)
            raise SystemExit(0)
    except (NmasError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"[ NMAS ] FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
