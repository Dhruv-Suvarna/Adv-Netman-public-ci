#!/usr/bin/env python3
"""Run inside an approved Ubuntu router (R3/R4) via stdin; payload:
{"config": <rsyslog.conf text>}.

No systemd inside R3/R4 -- installed/started the same way as the existing
Linux SNMP provisioning (provision_linux_snmp.py): a policy-rc.d guard stops
the package install from trying to invoke systemd, and the daemon is
started/stopped directly by pidfile, never via `systemctl`.
"""
import json
import pathlib
import subprocess
import sys
import time

payload = json.load(sys.stdin)


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


if subprocess.run(["dpkg-query", "-W", "-f=${Status}", "rsyslog"], capture_output=True, text=True).stdout != "install ok installed":
    # Container PID 1 is not systemd. Prevent package scripts starting a default agent.
    policy = pathlib.Path("/usr/sbin/policy-rc.d")
    original = policy.read_bytes() if policy.exists() else None
    mode = policy.stat().st_mode & 0o777 if policy.exists() else None
    try:
        policy.write_text("#!/bin/sh\nexit 101\n")
        policy.chmod(0o755)
        run("apt-get", "update")
        run("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "rsyslog")
    finally:
        if original is None:
            policy.unlink()
        else:
            policy.write_bytes(original)
            policy.chmod(mode)

# Ubuntu's shipped AppArmor profile for /usr/sbin/rsyslogd only grants read
# access to /etc/rsyslog.conf and /etc/rsyslog.d/**, and only allows the
# pidfile at /run/rsyslogd.pid -- verified live (a config/pidfile outside
# those paths fails with "Permission denied" even though the container has
# no other rsyslogd running). This is the one repository-owned file placed
# under a path the container's own AppArmor profile controls, rather than
# under /etc/nmas-syslog/ like every other NMAS runtime file.
config = pathlib.Path("/etc/rsyslog.d/nmas-syslog.conf")
changed = not config.exists() or config.read_text() != payload["config"]

pidfile = pathlib.Path("/run/rsyslogd.pid")
running = False
if pidfile.exists():
    pid = pidfile.read_text().strip()
    proc = pathlib.Path("/proc") / pid / "cmdline"
    running = proc.exists() and b"nmas-syslog.conf" in proc.read_bytes()

if changed and running:
    run("start-stop-daemon", "--stop", "--retry", "TERM/10/KILL/5", "--pidfile", str(pidfile), "--exec", "/usr/sbin/rsyslogd")
    running = False

if changed:
    config.write_text(payload["config"])
    config.chmod(0o644)

if not running:
    run("/usr/sbin/rsyslogd", "-f", str(config), "-i", str(pidfile))
    time.sleep(1)

print("rsyslog " + ("converged" if changed else "unchanged") + " pid=" + pidfile.read_text().strip())
