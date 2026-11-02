#!/usr/bin/env python3
"""Repository-owned substitute for the cEOS-lab remote-syslog transport.

This container's own rsyslogd -- the process EOS's `logging host` / `logging
trap critical` configuration depends on to actually transmit messages -- is
permanently crash-looping in this specific cEOS-lab build: its EOS-generated
/etc/rsyslog.conf loads an `improg` input that execs
/usr/bin/tracepointReader, which fails with "Permission denied" every
startup attempt (verified via `journalctl -u rsyslog`), gated by the
internal Arista `TracepointReader` engineering toggle -- not by anything
this repository configures, and not fixable by editing the generated
rsyslog.conf (EOS's SuperServer/LogMgr agent rewrites that file within
under a second of any change, tied to the crash-restart cycle itself). See
docs/SYSLOG_IMPLEMENTATION.md for the full verified evidence chain.

EOS keeps writing its own locally generated, severity-tagged events (format
"%FACILITY-N-MNEMONIC: message", where N is the syslog severity digit
0-7) to /var/log/messages independently of rsyslogd/journald -- confirmed:
neither process is involved in populating that file. This watcher tails it
from the current end-of-file (so a restart never replays history), and for
severity 0/1/2 (emerg/alert/crit -- matching the device's configured
`logging trap critical` policy) relays the line to NMAS as a direct
RFC 5424 UDP syslog packet tagged with facility local4 (matching the
device's `logging facility`), bypassing the broken local daemon entirely.

Deployed to /mnt/flash/nmas-syslog-forward.py and run under a small
repository-owned systemd unit (cEOS-lab's own systemd is healthy; only
rsyslog.service is broken) -- see
monitoring/scripts/provision_ceos_syslog_forwarder.py.
"""
import re
import subprocess
import time

LOGFILE = "/var/log/messages"
RECEIVER = "__RECEIVER__"
PORT = "__PORT__"
MAX_SEVERITY = __MAX_SEVERITY__

SEVERITY_PATTERN = re.compile(r"%[A-Za-z0-9_]+-([0-7])-[A-Za-z0-9_]+:")
SEVERITY_NAMES = {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning", 5: "notice", 6: "info", 7: "debug"}


def tail(path):
    handle = None
    while handle is None:
        try:
            handle = open(path, "r")
        except FileNotFoundError:
            time.sleep(2)
    handle.seek(0, 2)  # start at current end-of-file; never replay history on (re)start
    while True:
        line = handle.readline()
        if not line:
            time.sleep(1)
            continue
        yield line.rstrip("\n")


def forward(line):
    match = SEVERITY_PATTERN.search(line)
    if not match:
        return
    severity = int(match.group(1))
    if severity > MAX_SEVERITY:
        return
    subprocess.run(
        [
            "logger", "-n", RECEIVER, "-P", str(PORT), "--udp", "--rfc5424=notq",
            "-p", "local4." + SEVERITY_NAMES[severity], "-t", "EOS-CRITWATCH", line[:900],
        ],
        check=False, timeout=5,
    )


def main():
    for line in tail(LOGFILE):
        forward(line)


if __name__ == "__main__":
    main()
