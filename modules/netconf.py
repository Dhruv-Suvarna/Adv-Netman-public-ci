"""NETCONF capability proof and read-only verification for the deployed
inventory. cEOS NETCONF (`management api netconf transport ssh default`) was
already enabled fleet-wide in the baseline startup configuration -- verified
live, see docs/STREAMING_TELEMETRY_IMPLEMENTATION.md -- so this module makes
no cEOS NETCONF configuration changes. It authenticates as the same dedicated
`nmas-telemetry` identity modules/gnmi.py creates: cEOS uses its local AAA
database, while R3/R4 use the adapter's protected credential file.

R3/R4 (Ubuntu 24.04 + FRRouting 8.4.4) use the explicitly labelled,
repository-owned read-only lab adapter in modules/linux_telemetry_adapter.py;
this is not represented as native FRR NETCONF support.

IMPORTANT PROTOCOL SEMANTICS: this module only ever performs NETCONF
<get>/<hello> RPCs (structured request/response). cEOS 4.36.2F's NETCONF
server advertises no `:notification`, `:interleave`, `subscribed-notifications`,
or YANG Push capability (verified live, capability list stored for every
device in netconf-verification.json) -- so nothing here is a subscription or
push stream, and none of it is described as one.
"""
from __future__ import annotations

import json
import time
import warnings

from modules.gnmi import RUNTIME, TELEMETRY_USERNAME, credentials, devices, protected_json
from modules.nmas import NmasError
from modules.snmp import influx, tag

warnings.filterwarnings("ignore", module="ncclient")

HOSTNAME_FILTER = '<filter type="subtree"><system xmlns="http://openconfig.net/yang/system"><state><hostname/></state></system></filter>'
INTERFACES_FILTER = '<filter type="subtree"><interfaces xmlns="http://openconfig.net/yang/interfaces"><interface><name/></interface></interfaces></filter>'


def connect(item, password):
    from ncclient import manager
    # hostkey_verify=False: containerlab regenerates ephemeral SSH host keys
    # per deployment and this repo does not pin them; documented as an
    # accepted lab-scope limitation (transport confidentiality/integrity via
    # SSH is still in effect -- this only skips host-identity pinning).
    return manager.connect(
        host=item["address"], port=830, username=TELEMETRY_USERNAME, password=password,
        hostkey_verify=False, device_params={"name": "default"}, timeout=15,
        allow_agent=False, look_for_keys=False,
    )


def verify_device(item, password):
    with connect(item, password) as m:
        capabilities = sorted(str(c) for c in m.server_capabilities)
        if not any("netconf:base" in c for c in capabilities):
            raise NmasError(item["device"] + ": NETCONF hello did not advertise a base capability")

        hostname_reply = m.get(filter=HOSTNAME_FILTER).xml
        if f"<hostname>{item['device']}</hostname>" not in hostname_reply:
            raise NmasError(item["device"] + ": NETCONF hostname GET did not match inventory")

        interfaces_reply = m.get(filter=INTERFACES_FILTER).xml
        interface_count = interfaces_reply.count("<name>")
        if interface_count == 0:
            raise NmasError(item["device"] + ": NETCONF interfaces GET returned no interfaces")

        has_notifications = any(":notification" in c for c in capabilities)
        has_yang_push = any("yang-push" in c or "subscribed-notifications" in c for c in capabilities)

    return {
        "device": item["device"], "platform": item["platform"],
        "capabilities_count": len(capabilities), "interface_count": interface_count,
        "has_notifications": has_notifications, "has_yang_push": has_yang_push,
        "capabilities_sample": capabilities[:5],
    }


def store_snapshot(result):
    session, env = influx()
    stamp = time.time_ns()
    tags = f'device={tag(result["device"])},platform={tag(result["platform"])},source_protocol=netconf'
    fields = (
        f'capabilities_count={result["capabilities_count"]}i,'
        f'interface_count={result["interface_count"]}i,'
        f'has_notifications={"true" if result["has_notifications"] else "false"},'
        f'has_yang_push={"true" if result["has_yang_push"] else "false"}'
    )
    line = f"netconf_snapshot,{tags} {fields} {stamp}"
    r = session.post("http://127.0.0.1:8086/api/v2/write", params={"org": env["INFLUXDB_ORG"], "bucket": env["INFLUXDB_BUCKET"], "precision": "ns"}, data=line, timeout=15)
    r.raise_for_status()
    query = (f'from(bucket: {json.dumps(env["INFLUXDB_BUCKET"])}) |> range(start: time(v: {stamp}), stop: time(v: {stamp + 1})) '
             f'|> filter(fn: (r) => r._measurement == "netconf_snapshot" and r.device == "{result["device"]}")')
    r = session.post("http://127.0.0.1:8086/api/v2/query", params={"org": env["INFLUXDB_ORG"]}, headers={"Content-Type": "application/vnd.flux"}, data=query, timeout=15)
    r.raise_for_status()
    if result["device"] not in r.text:
        raise NmasError(result["device"] + ": InfluxDB query did not return the new netconf_snapshot sample")


def verify_netconf(items=None):
    items = items if items is not None else devices()
    password = credentials()["password"]
    results, failed = [], []
    print("DEVICE     NETCONF HELLO CAPS GET  NOTIF")
    for item in items:
        try:
            result = verify_device(item, password)
            store_snapshot(result)
            results.append(result)
            notif_note = "n/a (unsupported)" if not result["has_notifications"] else "supported"
            print(f'{item["device"]:<10} PASS    PASS  PASS PASS {notif_note}', flush=True)
        except Exception as exc:
            failed.append(item["device"])
            print(item["device"] + ": FAIL " + str(exc), flush=True)
    protected_json(RUNTIME / "netconf-verification.json", results)
    if failed:
        raise NmasError("NETCONF verification failed: " + ", ".join(failed))
    return results
