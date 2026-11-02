#!/usr/bin/env python3
"""Converge the gNMI and NETCONF telemetry adapters inside R3/R4.

This script is executed inside an Ubuntu/FRR router with a JSON payload on
stdin.  Those containers do not run systemd as PID 1, so adapter processes
are managed directly with pidfiles and start-stop-daemon.  No FRR, interface,
routing, addressing, VLAN, NAT, or DHCP state is read or changed here.
"""
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time


payload = json.load(sys.stdin)
BASE = pathlib.Path("/etc/nmas-telemetry")


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def imports_available():
    return subprocess.run(
        ["python3", "-c", "import grpc, google.protobuf, paramiko"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


changed = False
if not imports_available():
    policy = pathlib.Path("/usr/sbin/policy-rc.d")
    original = policy.read_bytes() if policy.exists() else None
    mode = policy.stat().st_mode & 0o777 if policy.exists() else None
    try:
        policy.write_text("#!/bin/sh\nexit 101\n")
        policy.chmod(0o755)
        run("apt-get", "update")
        run(
            "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
            "python3-grpcio", "python3-protobuf", "python3-paramiko", "openssl",
        )
    finally:
        if original is None:
            policy.unlink(missing_ok=True)
        else:
            policy.write_bytes(original)
            policy.chmod(mode)
    changed = True

if not imports_available():
    raise SystemExit("required Python telemetry adapter imports are unavailable")

BASE.mkdir(exist_ok=True)
os.chown(BASE, 0, 0)
BASE.chmod(0o700)


def write_if_changed(path, text, mode):
    global changed
    if path.is_symlink():
        raise SystemExit("refusing to replace symlink: " + str(path))
    content_changed = not path.exists() or path.read_text() != text
    metadata_changed = path.exists() and (
        path.stat().st_mode & 0o777 != mode
        or path.stat().st_uid != 0
        or path.stat().st_gid != 0
    )
    if content_changed:
        path.write_text(text)
    if content_changed or metadata_changed:
        path.chmod(mode)
        os.chown(path, 0, 0)
        changed = True


for name, text in payload["files"].items():
    write_if_changed(BASE / name, text, 0o644)

credentials_text = (
    "TELEMETRY_USERNAME=" + payload["username"] + "\n"
    "TELEMETRY_PASSWORD=" + payload["password"] + "\n"
)
write_if_changed(BASE / "credentials.env", credentials_text, 0o600)

tls = BASE / "tls"
tls.mkdir(exist_ok=True)
os.chown(tls, 0, 0)
tls.chmod(0o700)
cert = tls / "server.crt"
key = tls / "server.key"
if not cert.exists() or not key.exists():
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "3650",
        "-subj", "/CN=" + payload["device"],
        "-addext", "subjectAltName=DNS:" + payload["device"] + ",IP:" + payload["address"],
    )
    changed = True
for path, mode in ((cert, 0o644), (key, 0o600)):
    if path.is_symlink() or not path.is_file():
        raise SystemExit("missing or unsafe TLS file: " + str(path))
    if path.stat().st_mode & 0o777 != mode or path.stat().st_uid != 0 or path.stat().st_gid != 0:
        path.chmod(mode)
        os.chown(path, 0, 0)
        changed = True
run("openssl", "x509", "-checkend", "86400", "-noout", "-in", str(cert))

for log_name in ("nmas-gnmi-adapter.log", "nmas-netconf-adapter.log"):
    log_path = pathlib.Path("/var/log") / log_name
    if not log_path.exists():
        log_path.touch(mode=0o644)
    os.chown(log_path, 0, 0)
    log_path.chmod(0o644)


def cmdline(pid):
    try:
        return [part.decode(errors="replace") for part in (pathlib.Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0") if part]
    except (FileNotFoundError, PermissionError, ValueError):
        return []


def matching_pids(script):
    names = {script.name, str(script)}
    matches = []
    for proc in pathlib.Path("/proc").iterdir():
        if proc.name.isdigit() and names.intersection(cmdline(proc.name)):
            matches.append(int(proc.name))
    return matches


def stop_pids(pids):
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.time() + 10
    while time.time() < deadline and any(cmdline(pid) for pid in pids):
        time.sleep(0.2)
    for pid in pids:
        if cmdline(pid):
            os.kill(pid, signal.SIGKILL)


def ensure_process(name, script_name, port):
    global changed
    script = BASE / script_name
    pidfile = pathlib.Path("/run/nmas-" + name + "-adapter.pid")
    managed_pid = None
    if pidfile.exists():
        try:
            candidate = int(pidfile.read_text().strip())
        except ValueError:
            candidate = 0
        if str(script) in cmdline(candidate):
            managed_pid = candidate

    matches = matching_pids(script)
    if changed and managed_pid is not None:
        stop_pids([managed_pid])
        managed_pid = None
    stray = [pid for pid in matches if pid != managed_pid]
    if stray:
        # This adopts the hand-built proof of concept into pidfile-managed IaC
        # on the first run; only exact adapter argv entries are eligible.
        stop_pids(stray)
        changed = True

    if managed_pid is None:
        pidfile.unlink(missing_ok=True)
        run(
            "start-stop-daemon", "--start", "--background", "--make-pidfile",
            "--pidfile", str(pidfile), "--startas", "/usr/bin/python3", "--",
            str(script), payload["address"], str(port),
        )
        changed = True
        time.sleep(2)
        managed_pid = int(pidfile.read_text().strip())

    if str(script) not in cmdline(managed_pid):
        raise SystemExit(name + " adapter failed to stay running")
    with socket.create_connection((payload["address"], port), timeout=5):
        pass
    return managed_pid


gnmi_pid = ensure_process("gnmi", "linux_gnmi_server.py", 6030)
netconf_pid = ensure_process("netconf", "linux_netconf_server.py", 830)
print(
    "telemetry adapters " + ("converged" if changed else "unchanged")
    + "; gnmi_pid=" + str(gnmi_pid) + "; netconf_pid=" + str(netconf_pid)
)
