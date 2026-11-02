#!/usr/bin/env python3
"""Root-only, content-aware convergence for nmas-topology.service."""
import json
import pathlib
import socket
import subprocess
import sys
import time

payload = json.load(sys.stdin)


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


etc = pathlib.Path("/etc/nmas-topology")
etc.mkdir(exist_ok=True)
run("chown", "root:root", str(etc))
etc.chmod(0o755)
changed = False


def write_if_changed(path, content, mode):
    global changed
    if not path.exists() or path.read_text() != content:
        path.write_text(content)
        path.chmod(mode)
        run("chown", "root:root", str(path))
        changed = True


write_if_changed(etc / "topology_server.py", payload["server_script"], 0o755)
write_if_changed(etc / "topology_graph.py", payload["graph_module"], 0o644)
write_if_changed(etc / "topology.json", json.dumps(payload["topology"], sort_keys=True), 0o644)
write_if_changed(etc / "config.json", json.dumps(payload["config"], sort_keys=True), 0o644)
write_if_changed(
    etc / "influx.env",
    "INFLUXDB_ORG=" + payload["influx_org"] + "\n"
    "INFLUXDB_BUCKET=" + payload["influx_bucket"] + "\n"
    "INFLUXDB_TOKEN=" + payload["influx_token"] + "\n",
    0o600,
)

unit = pathlib.Path("/etc/systemd/system/nmas-topology.service")
unit_text = (
    "[Unit]\n"
    "Description=NMAS NetworkX dynamic topology (read-only)\n"
    "After=network.target docker.service nmas-gnmi-collector.service\n\n"
    "[Service]\n"
    "Type=simple\n"
    "EnvironmentFile=/etc/nmas-topology/influx.env\n"
    "ExecStart=" + payload["python"] + " /etc/nmas-topology/topology_server.py\n"
    "WorkingDirectory=/etc/nmas-topology\n"
    # Match the existing gNMI service's root-owned shared virtualenv.  The
    # remaining unit sandboxing leaves this read-only API no writable system
    # paths and the listener is restricted to localhost.
    "User=root\n"
    "Group=root\n"
    "Restart=always\n"
    "RestartSec=3\n"
    "NoNewPrivileges=true\n"
    "PrivateTmp=true\n"
    # The approved repository virtualenv lives under /home/student.  Keep it
    # visible but immutable to this unprivileged service.
    "ProtectHome=read-only\n"
    "ProtectSystem=strict\n"
    "RestrictSUIDSGID=true\n\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)
if not unit.exists() or unit.read_text() != unit_text:
    unit.write_text(unit_text)
    unit.chmod(0o644)
    run("chown", "root:root", str(unit))
    run("systemctl", "daemon-reload")
    changed = True

active = subprocess.run(
    ["systemctl", "is-active", "nmas-topology.service"], capture_output=True, text=True,
).stdout.strip()
if changed:
    run("systemctl", "enable", "--now", "nmas-topology.service")
    run("systemctl", "restart", "nmas-topology.service")
elif active != "active":
    run("systemctl", "enable", "--now", "nmas-topology.service")

active = subprocess.run(
    ["systemctl", "is-active", "nmas-topology.service"], capture_output=True, text=True,
).stdout.strip()
if active != "active":
    raise SystemExit("nmas-topology.service failed to become active")
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    try:
        with socket.create_connection(
            (payload["config"]["bind_address"], int(payload["config"]["port"])), timeout=1,
        ):
            break
    except OSError:
        time.sleep(0.25)
else:
    raise SystemExit("nmas-topology.service did not open its localhost listener")
pid = subprocess.run(
    ["systemctl", "show", "-p", "MainPID", "--value", "nmas-topology.service"],
    capture_output=True, text=True,
).stdout.strip()
print(
    "NetworkX topology " + ("converged" if changed else "unchanged")
    + "; nodes=" + str(len(payload["topology"]["nodes"]))
    + "; edges=" + str(len(payload["topology"]["edges"]))
    + "; active=" + active + "; pid=" + pid
)
