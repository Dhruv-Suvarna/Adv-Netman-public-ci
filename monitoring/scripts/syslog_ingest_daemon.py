#!/usr/bin/env python3
"""Standalone NMAS-side tailer, deployed to
/etc/nmas-syslog/syslog_ingest_daemon.py and run as its own systemd service
(nmas-syslog-ingest.service) rather than as a child of rsyslogd.

rsyslog's `omprog` action was tried first (a child-process pipe, the same
shape as the existing SNMP trap `traphandle` ingestion) but Ubuntu 24.04's
shipped AppArmor profile for /usr/sbin/rsyslogd
(/etc/apparmor.d/usr.sbin.rsyslogd) grants no exec permission at all, so
every omprog invocation failed with "Permission denied" -- confirmed live
via `journalctl -u rsyslog`. Loosening that host-wide security policy for a
lab convenience was judged out of proportion to the benefit, so this
process reads the *existing*, unmodified raw log file instead of being
spawned by rsyslog: /var/log/lab-monitoring/remote-syslog.log, written by
the pre-existing `lab-network` ruleset in
monitoring/config/rsyslog-lab-monitoring.conf (never modified by this
script -- it is opened read-only).

Tracks a byte offset across restarts (/var/lib/nmas-syslog-ingest/offset)
so a restart never re-ingests old lines and never silently skips new ones;
detects truncation/rotation (logrotate's `copytruncate`) by noticing the
file has shrunk and restarting from the new end.
"""
import json
import pathlib
import re
import time
from datetime import datetime, timezone

LOGFILE = pathlib.Path("/var/log/lab-monitoring/remote-syslog.log")
STATE_DIR = pathlib.Path("/var/lib/nmas-syslog-ingest")
OFFSET_FILE = STATE_DIR / "offset"
ETC = pathlib.Path("/etc/nmas-syslog")
INGEST_LOG = pathlib.Path("/var/log/nmas-syslog-ingest.log")

LINE = re.compile(
    r"^(?P<ts>\S+) device=(?P<device>\S+) source=(?P<source>\S+) "
    r"facility=(?P<facility>\S+) severity=(?P<severity>\S+) message=(?P<message>.*)$"
)

SEVERITY_CODES = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}
FACILITY_CODES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
    "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}


def log(message):
    try:
        with INGEST_LOG.open("a") as stream:
            stream.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + message + "\n")
    except OSError:
        pass


def tag(value):
    return str(value).replace("\\", "\\\\").replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def field_str(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def load_env():
    return dict(line.split("=", 1) for line in (ETC / "ingest.env").read_text().splitlines() if "=" in line)


def load_devices():
    try:
        return json.loads((ETC / "devices.json").read_text())
    except (OSError, ValueError):
        return {}


def to_nanos(ts):
    try:
        return int(datetime.fromisoformat(ts).astimezone(timezone.utc).timestamp() * 1_000_000_000)
    except ValueError:
        return time.time_ns()


def build_point(match, devices):
    g = match.groupdict()
    hostname = g["device"]
    entry = devices.get(hostname, {})
    device = entry.get("device", hostname) if isinstance(entry, dict) else hostname
    platform = entry.get("platform", "") if isinstance(entry, dict) else ""
    severity_code = SEVERITY_CODES.get(g["severity"], 8)
    facility_code = FACILITY_CODES.get(g["facility"], -1)
    tags = (
        f'device={tag(device)},source_ip={tag(g["source"])},source_protocol=syslog,'
        f'severity={tag(g["severity"])},facility={tag(g["facility"])}'
    )
    if platform:
        tags += f",platform={tag(platform)}"
    fields = (
        f'message={field_str(g["message"])},hostname={field_str(hostname)},'
        f"severity_code={severity_code}i,facility_code={facility_code}i"
    )
    return f"syslog_event,{tags} {fields} {to_nanos(g['ts'])}"


def main():
    import requests

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    offset = int(OFFSET_FILE.read_text()) if OFFSET_FILE.exists() else (LOGFILE.stat().st_size if LOGFILE.exists() else 0)
    session = requests.Session()
    while True:
        if not LOGFILE.exists():
            time.sleep(2)
            continue
        size = LOGFILE.stat().st_size
        if size < offset:
            log(f"raw log shrank ({size} < {offset}); assuming rotation, resuming at new end")
            offset = 0
        with LOGFILE.open("r", errors="replace") as handle:
            handle.seek(offset)
            lines = handle.readlines()
            offset = handle.tell()
        OFFSET_FILE.write_text(str(offset))
        if not lines:
            time.sleep(1)
            continue
        try:
            devices = load_devices()
            env = load_env()
        except (OSError, KeyError) as exc:
            log("FAIL cannot load config: " + str(exc))
            time.sleep(2)
            continue
        points = [build_point(m, devices) for m in (LINE.match(raw.rstrip("\n")) for raw in lines) if m]
        if not points:
            continue
        try:
            response = session.post(
                "http://127.0.0.1:8086/api/v2/write",
                params={"org": env["INFLUXDB_ORG"], "bucket": env["INFLUXDB_BUCKET"], "precision": "ns"},
                headers={"Authorization": "Token " + env["INFLUXDB_TOKEN"]},
                data="\n".join(points),
                timeout=10,
            )
            response.raise_for_status()
            log(f"OK wrote {len(points)} point(s)")
        except Exception as exc:
            log(f"FAIL InfluxDB write: {exc}")


if __name__ == "__main__":
    main()
