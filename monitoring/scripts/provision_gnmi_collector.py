#!/usr/bin/env python3
"""Root-only convergence for the NMAS-side gNMI-to-InfluxDB streaming
collector, invoked via `sudo -n python3 -c <script>` with a JSON payload on
stdin -- deploys monitoring/scripts/gnmi_collector.py, per-device CA
certificates, the stream-path inventory, protected credential files, and
runs the collector as its own systemd unit. Mirrors
provision_syslog_receiver.py's convergence/idempotency shape.
"""
import json
import pathlib
import subprocess
import sys

payload = json.load(sys.stdin)


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


etc = pathlib.Path("/etc/nmas-gnmi")
etc.mkdir(exist_ok=True)
run("chown", "root:root", str(etc))
etc.chmod(0o755)

changed = False


def write_if_changed(path, text, mode):
    global changed
    if not path.exists() or path.read_text() != text:
        path.write_text(text)
        path.chmod(mode)
        run("chown", "root:root", str(path))
        changed = True


write_if_changed(etc / "gnmi_collector.py", payload["collector_script"], 0o755)
write_if_changed(etc / "devices.json", json.dumps(payload["devices"], sort_keys=True), 0o644)
write_if_changed(etc / "paths.json", json.dumps(payload["paths"], sort_keys=True), 0o644)

ca_dir = etc / "ca"
ca_dir.mkdir(exist_ok=True)
run("chown", "root:root", str(ca_dir))
ca_dir.chmod(0o755)
for entry in payload["devices"]:
    write_if_changed(ca_dir / (entry["device"] + ".crt"), entry["ca_cert"], 0o644)

credentials_text = (
    "TELEMETRY_USERNAME=" + payload["username"] + "\n"
    "TELEMETRY_PASSWORD=" + payload["password"] + "\n"
)
write_if_changed(etc / "credentials.env", credentials_text, 0o600)

ingest_text = (
    "INFLUXDB_ORG=" + payload["influx_org"] + "\n"
    "INFLUXDB_BUCKET=" + payload["influx_bucket"] + "\n"
    "INFLUXDB_TOKEN=" + payload["influx_token"] + "\n"
)
write_if_changed(etc / "ingest.env", ingest_text, 0o600)

log_path = pathlib.Path("/var/log/nmas-gnmi-collector.log")
if not log_path.exists():
    log_path.touch()
    log_path.chmod(0o644)

unit_path = pathlib.Path("/etc/systemd/system/nmas-gnmi-collector.service")
unit_text = (
    "[Unit]\n"
    "Description=NMAS gNMI Subscribe (STREAM+SAMPLE) collector -> InfluxDB\n"
    "After=network.target docker.service\n\n"
    "[Service]\n"
    "ExecStart=" + payload["python"] + " /etc/nmas-gnmi/gnmi_collector.py\n"
    "Restart=always\n"
    "RestartSec=3\n"
    "User=root\n\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)
unit_changed = not unit_path.exists() or unit_path.read_text() != unit_text
if unit_changed:
    unit_path.write_text(unit_text)
    unit_path.chmod(0o644)
    run("systemctl", "daemon-reload")
    changed = True

active = subprocess.run(["systemctl", "is-active", "nmas-gnmi-collector.service"], capture_output=True, text=True).stdout.strip()
if changed:
    run("systemctl", "enable", "--now", "nmas-gnmi-collector.service")
    run("systemctl", "restart", "nmas-gnmi-collector.service")
elif active != "active":
    run("systemctl", "enable", "--now", "nmas-gnmi-collector.service")

active = subprocess.run(["systemctl", "is-active", "nmas-gnmi-collector.service"], capture_output=True, text=True).stdout.strip()
if active != "active":
    raise SystemExit("nmas-gnmi-collector.service failed to become active")

pid = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "nmas-gnmi-collector.service"], capture_output=True, text=True).stdout.strip()
print("gNMI collector " + ("converged" if changed else "unchanged") + "; " + str(len(payload["devices"])) + " devices mapped; active=" + active + "; pid=" + pid)
