#!/usr/bin/env python3
"""Root-context convergence for the NMAS critical-syslog forwarder inside a
cEOS-lab container. Payload arrives on stdin: {"script": <forwarder source>}.

cEOS-lab runs a real, healthy systemd (PID 1) -- only rsyslog.service itself
is broken (see ceos_syslog_forward.py) -- so this uses a normal systemd unit
rather than the systemd-free start-stop-daemon pattern R3/R4 needs.
"""
import json
import pathlib
import subprocess
import sys

payload = json.load(sys.stdin)


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


script_path = pathlib.Path("/mnt/flash/nmas-syslog-forward.py")
unit_path = pathlib.Path("/etc/systemd/system/nmas-syslog-forward.service")
unit_text = (
    "[Unit]\n"
    "Description=NMAS critical-syslog forwarder (works around broken cEOS-lab rsyslogd)\n"
    "After=network.target\n\n"
    "[Service]\n"
    "ExecStart=/usr/bin/python3 /mnt/flash/nmas-syslog-forward.py\n"
    "Restart=always\n"
    "RestartSec=2\n"
    "User=root\n\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)

script_changed = not script_path.exists() or script_path.read_text() != payload["script"]
unit_changed = not unit_path.exists() or unit_path.read_text() != unit_text

if script_changed:
    script_path.write_text(payload["script"])
    script_path.chmod(0o644)
if unit_changed:
    unit_path.write_text(unit_text)
    unit_path.chmod(0o644)
    run("systemctl", "daemon-reload")

active = subprocess.run(["systemctl", "is-active", "nmas-syslog-forward.service"], capture_output=True, text=True).stdout.strip()
if script_changed or unit_changed:
    run("systemctl", "enable", "--now", "nmas-syslog-forward.service")
    run("systemctl", "restart", "nmas-syslog-forward.service")
elif active != "active":
    run("systemctl", "enable", "--now", "nmas-syslog-forward.service")

active = subprocess.run(["systemctl", "is-active", "nmas-syslog-forward.service"], capture_output=True, text=True).stdout.strip()
if active != "active":
    raise SystemExit("nmas-syslog-forward.service failed to become active")
print("forwarder " + ("converged" if (script_changed or unit_changed) else "unchanged") + "; active=" + active)
