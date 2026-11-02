#!/usr/bin/env python3
"""Standalone NMAS-side gNMI Subscribe (STREAM+SAMPLE) collector, deployed to
/etc/nmas-gnmi/gnmi_collector.py and run as its own systemd service
(nmas-gnmi-collector.service) using the repository's Python virtualenv
(pygnmi/grpcio live there, not in system python3).

One reconnecting thread per monitored device (the eight cEOS nodes plus the
explicitly labelled R3/R4 Linux/FRR telemetry adapters),
each holding a persistent gNMI Subscribe session over TLS. Parsed updates are
pushed onto a shared queue; a single writer thread batches them into
InfluxDB line protocol and POSTs to the existing `network-monitoring` bucket
as the `gnmi_telemetry` measurement. A connection failure only restarts that
device's own thread (logged, backoff, reconnect) -- it never brings down the
rest of the collector.

On-disk config (all written by monitoring/scripts/provision_gnmi_collector.py):
  /etc/nmas-gnmi/devices.json      -- [{device, platform, address, port}, ...]
  /etc/nmas-gnmi/ca/<device>.crt   -- per-device lab CA for TLS validation
  /etc/nmas-gnmi/paths.json        -- monitoring/config/gnmi_paths.yml, as JSON
  /etc/nmas-gnmi/credentials.env   -- TELEMETRY_USERNAME / TELEMETRY_PASSWORD
  /etc/nmas-gnmi/ingest.env        -- INFLUXDB_ORG / INFLUXDB_BUCKET / INFLUXDB_TOKEN
"""
import json
import queue
import re
import threading
import time
import traceback
from pathlib import Path

ETC = Path("/etc/nmas-gnmi")
LOG_PATH = Path("/var/log/nmas-gnmi-collector.log")

# Only these container keys are stored per category -- keeps the schema
# small and excludes fields not in the documented stream inventory
# (docs/TELEMETRY_STREAMS.md), even though the device sends more.
COUNTER_FIELDS = {
    "in-octets": "in_octets", "out-octets": "out_octets",
    "in-errors": "in_errors", "out-errors": "out_errors",
    "in-discards": "in_discards", "out-discards": "out_discards",
}
MEMORY_FIELDS = {
    "physical": "mem_physical_bytes", "used": "mem_used_bytes",
    "free": "mem_free_bytes", "reserved": "mem_reserved_bytes",
}
SCALAR_FIELDS = {"instant": "cpu_total_pct", "oper-status": "oper_status", "admin-status": "admin_status", "hostname": "hostname"}


def log(message):
    try:
        with LOG_PATH.open("a") as stream:
            stream.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + message + "\n")
    except OSError:
        pass


def load_env(name):
    return dict(line.split("=", 1) for line in (ETC / name).read_text().splitlines() if "=" in line)


def tag_escape(value):
    return str(value).replace("\\", "\\\\").replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def field_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return f"{int(value)}i"
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value):
        return f"{int(value)}i"
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def path_to_dict(path_msg):
    keys, parts = {}, []
    for elem in path_msg.elem:
        parts.append(elem.name)
        for k, v in elem.key.items():
            keys[k] = v
    return "/".join(parts), keys


def decode_val(val):
    kind = val.WhichOneof("value")
    raw = getattr(val, kind)
    if kind == "json_ietf_val":
        data = json.loads(raw.decode() if isinstance(raw, (bytes, bytearray)) else raw)
        if isinstance(data, dict):
            return {k.split(":")[-1]: v for k, v in data.items()}, True
        return data, False
    return raw, False


def classify(full_path, keys, value, is_container, device, platform):
    """Return a gnmi_telemetry line-protocol string, or None to skip."""
    tags = {"device": device, "platform": platform, "source_protocol": "gnmi"}
    fields = {}

    if full_path.startswith("system/state") and full_path.endswith("hostname"):
        tags["category"] = "system_identity"
        fields["hostname"] = value
    elif full_path.startswith("system/cpus/cpu"):
        tags["category"] = "system_cpu"
        tags["cpu_index"] = keys.get("index", "0")
        leaf = full_path.rsplit("/", 1)[-1]
        fields[SCALAR_FIELDS.get(leaf, leaf)] = value
    elif full_path.startswith("system/memory/state"):
        tags["category"] = "system_memory"
        if is_container:
            # A whole-container blob (e.g. from Get(), or a server that
            # sends json_ietf_val for a container path).
            for k, v in value.items():
                if k in MEMORY_FIELDS:
                    fields[MEMORY_FIELDS[k]] = v
        else:
            # cEOS's real Subscribe stream does NOT send a container blob for
            # `/system/memory/state` -- verified live: it decomposes the
            # container into individual scalar leaf updates (one Update per
            # sub-field, several sharing one Notification via a common
            # `prefix`), each arriving here as its own classify() call with
            # is_container=False. Handling only the container case silently
            # dropped every system_memory point until this was caught by
            # querying InfluxDB and finding the category empty; see
            # docs/STREAMING_TELEMETRY_IMPLEMENTATION.md "Collector bug".
            leaf = full_path.rsplit("/", 1)[-1]
            if leaf in MEMORY_FIELDS:
                fields[MEMORY_FIELDS[leaf]] = value
    elif full_path.startswith("interfaces/interface"):
        iface = keys.get("name")
        if not iface:
            return None
        tags["interface"] = iface
        if full_path.endswith("oper-status") or full_path.endswith("admin-status"):
            tags["category"] = "interface_state"
            leaf = full_path.rsplit("/", 1)[-1]
            fields[SCALAR_FIELDS[leaf]] = value
        elif "/state/counters" in full_path:
            tags["category"] = "interface_counters"
            if is_container:
                for k, v in value.items():
                    if k in COUNTER_FIELDS:
                        fields[COUNTER_FIELDS[k]] = v
            else:
                # Same decomposition behavior as system/memory/state above:
                # cEOS sends one scalar Update per counter leaf, not a blob.
                leaf = full_path.rsplit("/", 1)[-1]
                if leaf in COUNTER_FIELDS:
                    fields[COUNTER_FIELDS[leaf]] = value
        else:
            return None
    else:
        return None

    if not fields:
        return None
    tag_str = ",".join(f"{k}={tag_escape(v)}" for k, v in tags.items())
    field_str = ",".join(f"{k}={field_value(v)}" for k, v in fields.items())
    return f"gnmi_telemetry,{tag_str} {field_str}"


def build_subscribe_request(paths_config):
    interval = paths_config["sample_interval_ns"]
    return {
        "subscription": [{"path": s["path"], "mode": "sample", "sample_interval": interval} for s in paths_config["streams"]],
        "mode": "stream",
        "encoding": "json_ietf",
    }


def device_worker(device_cfg, creds, paths_config, out_queue, stop_event):
    from pygnmi.client import gNMIclient

    device, platform = device_cfg["device"], device_cfg["platform"]
    ca_path = str(ETC / "ca" / f"{device}.crt")
    subscribe = build_subscribe_request(paths_config)
    backoff = 2
    while not stop_event.is_set():
        try:
            with gNMIclient(
                target=(device_cfg["address"], device_cfg["port"]),
                username=creds["TELEMETRY_USERNAME"], password=creds["TELEMETRY_PASSWORD"],
                insecure=False, path_root=ca_path, override=device, gnmi_timeout=15,
            ) as gc:
                log(f"{device}: subscribed")
                backoff = 2
                for reply in gc.subscribe(subscribe=subscribe):
                    if stop_event.is_set():
                        break
                    if not reply.HasField("update"):
                        continue
                    notif = reply.update
                    prefix_path, prefix_keys = ("", {})
                    if notif.HasField("prefix"):
                        prefix_path, prefix_keys = path_to_dict(notif.prefix)
                    for upd in notif.update:
                        leaf_path, leaf_keys = path_to_dict(upd.path)
                        full_path = "/".join(p for p in (prefix_path, leaf_path) if p)
                        keys = {**prefix_keys, **leaf_keys}
                        value, is_container = decode_val(upd.val)
                        line = classify(full_path, keys, value, is_container, device, platform)
                        if line:
                            out_queue.put(line)
        except StopIteration:
            pass
        except Exception as exc:  # noqa: BLE001 -- must never take the whole collector down
            log(f"{device}: ERROR {exc!r}; reconnecting in {backoff}s")
        time.sleep(backoff)
        backoff = min(backoff * 2, 30)


def writer_worker(out_queue, stop_event):
    import requests

    session = requests.Session()
    batch = []
    last_flush = time.time()
    while not stop_event.is_set() or not out_queue.empty():
        try:
            batch.append(out_queue.get(timeout=1))
        except queue.Empty:
            pass
        if batch and (len(batch) >= 200 or time.time() - last_flush >= 5):
            try:
                env = load_env("ingest.env")
                stamp = time.time_ns()
                lines = "\n".join(f"{line} {stamp}" for line in batch)
                resp = session.post(
                    "http://127.0.0.1:8086/api/v2/write",
                    params={"org": env["INFLUXDB_ORG"], "bucket": env["INFLUXDB_BUCKET"], "precision": "ns"},
                    headers={"Authorization": "Token " + env["INFLUXDB_TOKEN"]},
                    data=lines, timeout=15,
                )
                resp.raise_for_status()
                log(f"wrote {len(batch)} point(s)")
            except Exception as exc:  # noqa: BLE001
                log(f"FAIL InfluxDB write: {exc}")
            batch = []
            last_flush = time.time()


def main():
    devices = json.loads((ETC / "devices.json").read_text())
    paths_config = json.loads((ETC / "paths.json").read_text())
    creds = load_env("credentials.env")

    out_queue = queue.Queue()
    stop_event = threading.Event()
    threads = [threading.Thread(target=writer_worker, args=(out_queue, stop_event), daemon=True)]
    for device_cfg in devices:
        threads.append(threading.Thread(target=device_worker, args=(device_cfg, creds, paths_config, out_queue, stop_event), daemon=True, name=device_cfg["device"]))
    for t in threads:
        t.start()
    log(f"started with {len(devices)} device(s)")
    try:
        while True:
            time.sleep(30)
    except KeyboardInterrupt:
        stop_event.set()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log("FATAL " + traceback.format_exc())
        raise
