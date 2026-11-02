#!/usr/bin/env python3
"""Root-only convergence for the NMAS-side syslog-to-InfluxDB ingestion
daemon, invoked via `sudo -n python3 -c <script>` with a JSON payload on
stdin -- deploys monitoring/scripts/syslog_ingest_daemon.py, a
device/platform lookup table, and a protected InfluxDB credential file, then
runs the daemon as its own systemd unit (never as a child of rsyslogd; see
docs/SYSLOG_IMPLEMENTATION.md for why).
"""
import json
import pathlib
import subprocess
import sys

payload = json.load(sys.stdin)


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


etc = pathlib.Path("/etc/nmas-syslog")
etc.mkdir(exist_ok=True)
run("chown", "root:root", str(etc))
etc.chmod(0o755)

changed = False

script_path = etc / "syslog_ingest_daemon.py"
if not script_path.exists() or script_path.read_text() != payload["daemon_script"]:
    script_path.write_text(payload["daemon_script"])
    script_path.chmod(0o755)
    run("chown", "root:root", str(script_path))
    changed = True

devices_path = etc / "devices.json"
devices_text = json.dumps(payload["devices"], sort_keys=True)
if not devices_path.exists() or devices_path.read_text() != devices_text:
    devices_path.write_text(devices_text)
    devices_path.chmod(0o644)
    run("chown", "root:root", str(devices_path))
    changed = True

env_path = etc / "ingest.env"
env_text = (
    "INFLUXDB_ORG=" + payload["influx_org"] + "\n"
    "INFLUXDB_BUCKET=" + payload["influx_bucket"] + "\n"
    "INFLUXDB_TOKEN=" + payload["influx_token"] + "\n"
)
if not env_path.exists() or env_path.read_text() != env_text:
    env_path.write_text(env_text)
    run("chown", "root:root", str(env_path))
    env_path.chmod(0o600)
    changed = True

log_path = pathlib.Path("/var/log/nmas-syslog-ingest.log")
if not log_path.exists():
    log_path.touch()
    log_path.chmod(0o644)

unit_path = pathlib.Path("/etc/systemd/system/nmas-syslog-ingest.service")
unit_text = (
    "[Unit]\n"
    "Description=NMAS syslog-to-InfluxDB ingestion (tails the existing raw log; never modifies it)\n"
    "After=network.target rsyslog.service\n\n"
    "[Service]\n"
    "ExecStart=" + payload["python"] + " /etc/nmas-syslog/syslog_ingest_daemon.py\n"
    "Restart=always\n"
    "RestartSec=2\n"
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

active = subprocess.run(["systemctl", "is-active", "nmas-syslog-ingest.service"], capture_output=True, text=True).stdout.strip()
if changed:
    run("systemctl", "enable", "--now", "nmas-syslog-ingest.service")
    run("systemctl", "restart", "nmas-syslog-ingest.service")
elif active != "active":
    run("systemctl", "enable", "--now", "nmas-syslog-ingest.service")

active = subprocess.run(["systemctl", "is-active", "nmas-syslog-ingest.service"], capture_output=True, text=True).stdout.strip()
if active != "active":
    raise SystemExit("nmas-syslog-ingest.service failed to become active")

print("Syslog ingestion " + ("converged" if changed else "unchanged") + "; " + str(len(payload["devices"])) + " devices mapped; active=" + active)
