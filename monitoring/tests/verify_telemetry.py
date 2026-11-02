#!/usr/bin/env python3
"""Automated capability/result matrix for streaming telemetry (gNMI) and
NETCONF, across every device in the deployed inventory.

Columns:
  GNMI      -- gNMI server reachable, TLS handshake OK, authenticated Capabilities+Get succeed
  STREAM    -- the persistent nmas-gnmi-collector.service Subscribe stream produced a point
  INFLUX    -- that point (or, for NETCONF, the snapshot) is queryable back from InfluxDB
  NETCONF   -- NETCONF hello/capabilities exchange succeeds
  NC-GET    -- a real read-only NETCONF <get> RPC returns data matching device state

R3/R4 (Ubuntu 24.04 + FRRouting 8.4.4) use the repository-owned, read-only
lab telemetry adapter.  PASS means the same real wire protocols and live
state/storage checks succeeded; it does not claim native FRR support.

Usage: monitoring/tests/verify_telemetry.py  (uses the repo virtualenv's
pygnmi/ncclient; run via `python3 master.py --telemetry-only`'s venv, or
directly with $NMAS_VENV/bin/python3 monitoring/tests/verify_telemetry.py)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.gnmi import credentials as gnmi_credentials, devices as gnmi_devices, verify_capabilities_and_get, verify_collector_stream
from modules.netconf import verify_device as netconf_verify_device
from modules.nmas import NmasError


def check_gnmi(item):
    try:
        verify_capabilities_and_get(item)
        return "PASS"
    except Exception as exc:
        return "FAIL(" + str(exc)[:40] + ")"


def check_stream_influx(item):
    try:
        verify_collector_stream([item], quiet=True)
        return "PASS", "PASS"
    except Exception as exc:
        return "FAIL", "FAIL(" + str(exc)[:30] + ")"


def check_netconf(item, password):
    try:
        result = netconf_verify_device(item, password)
        return "PASS", "PASS", result
    except Exception as exc:
        return "FAIL(" + str(exc)[:30] + ")", "FAIL", None


def main():
    items = gnmi_devices()
    password = gnmi_credentials()["password"]
    rows = []
    print(f'{"DEVICE":<10} {"GNMI":<6} {"STREAM":<6} {"INFLUX":<6} {"NETCONF":<8} {"NC-GET":<6}')
    failures = []
    for item in items:
        gnmi_col = check_gnmi(item)
        stream_col, influx_col = check_stream_influx(item)
        netconf_col, ncget_col, _ = check_netconf(item, password)
        rows.append((item["device"], gnmi_col, stream_col, influx_col, netconf_col, ncget_col))
        print(f'{item["device"]:<10} {gnmi_col:<6} {stream_col:<6} {influx_col:<6} {netconf_col:<8} {ncget_col:<6}')
        if "FAIL" in gnmi_col or "FAIL" in stream_col or "FAIL" in influx_col or "FAIL" in netconf_col or "FAIL" in ncget_col:
            failures.append(item["device"])

    print()
    if failures:
        print("FAIL: " + ", ".join(failures))
        raise SystemExit(1)
    print(f"PASS: all {len(items)} monitored devices fully verified over gNMI/NETCONF")


if __name__ == "__main__":
    try:
        main()
    except NmasError as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
