#!/usr/bin/env python3
"""Real OpenConfig gNMI gRPC server -- the NMAS Linux/FRR telemetry ADAPTER,
Part A (see docs/STREAMING_TELEMETRY_IMPLEMENTATION.md "R3/R4 adapter").

R3/R4 (Ubuntu 24.04 + FRRouting 8.4.4) have no native gNMI server. This is
NOT a simulation of one: it is a real gNMI gRPC service (Capabilities/Get/
Subscribe), built on the same generated OpenConfig gNMI protobuf/gRPC stubs
pygnmi uses client-side (deployed alongside this file as gnmi_pb2.py/
gnmi_pb2_grpc.py/gnmi_ext_pb2.py -- see modules/linux_telemetry_adapter.py
for how they're derived), speaking the real gNMI wire protocol over TLS.
Every value it returns comes from nmas_linux_telemetry_metrics.py reading
/proc and /sys/class/net on THIS router, live, at request/sample time.

Deliberately NOT implemented (advertised honestly, not silently missing):
  - Set (returns UNIMPLEMENTED -- read-only adapter, no config writes)
  - ON_CHANGE subscriptions (only STREAM+SAMPLE, matching the cEOS collector)
  - any OpenConfig model beyond openconfig-system/openconfig-interfaces

Subscribe wire behavior deliberately matches what cEOS's own gNMI server was
observed doing live (see docs/STREAMING_TELEMETRY_IMPLEMENTATION.md): a
container-shaped path (system/memory/state, .../state/counters) is NOT sent
as one json_ietf_val blob -- it is decomposed into individual scalar leaf
Updates (grouped under one Notification via a shared `prefix` where they
share a sample), so the *same* NMAS collector code that already parses
cEOS's real stream needs no per-vendor branch to parse this adapter's
stream too. Get() instead returns one json_ietf_val container blob per
container path requested, again matching real cEOS Get() behavior.
"""
import json
import pathlib
import socket
import sys
import threading
import time
from concurrent import futures

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gnmi_pb2 as pb          # noqa: E402
import gnmi_pb2_grpc as pb_grpc  # noqa: E402
import grpc                    # noqa: E402
import nmas_linux_telemetry_metrics as metrics  # noqa: E402

ETC = pathlib.Path("/etc/nmas-telemetry")
LOG_PATH = pathlib.Path("/var/log/nmas-gnmi-adapter.log")
CPU_INDEX = "0"  # a single system-wide aggregate, like cEOS's index=0


def log(message):
    try:
        with LOG_PATH.open("a") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + message + "\n")
    except OSError:
        pass


def load_env(name):
    return dict(line.split("=", 1) for line in (ETC / name).read_text().splitlines() if "=" in line)


def pe(elem_name, **keys):
    return pb.PathElem(name=elem_name, key={k: str(v) for k, v in keys.items()})


def scalar(**kwargs):
    return pb.TypedValue(**kwargs)


class MetricState:
    """Background sampler: keeps CPU utilization accurate (delta-based, not
    load average) independent of how often a client subscribes/polls."""

    def __init__(self):
        self._lock = threading.Lock()
        self._prev_cpu = metrics.cpu_snapshot()
        self._cpu_pct = 0
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            time.sleep(5)
            curr = metrics.cpu_snapshot()
            with self._lock:
                self._cpu_pct = metrics.cpu_percent(self._prev_cpu, curr)
                self._prev_cpu = curr

    def cpu_percent(self):
        with self._lock:
            return self._cpu_pct


STATE = MetricState()


def check_auth(context):
    md = dict(context.invocation_metadata())
    creds = load_env("credentials.env")
    if md.get("username") != creds.get("TELEMETRY_USERNAME") or md.get("password") != creds.get("TELEMETRY_PASSWORD"):
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid credentials")


# --------------------------------------------------------------------------
# Notification builders -- one function per stream category, each reading
# live state at call time. Mirrors monitoring/config/gnmi_paths.yml exactly.
# --------------------------------------------------------------------------

def notif_hostname(ts):
    n = pb.Notification(timestamp=ts)
    n.update.add(path=pb.Path(elem=[pe("system"), pe("state"), pe("hostname")]), val=scalar(string_val=metrics.hostname()))
    return [n]


def path_elem_key(path, element, key):
    """Return one PathElem key without flattening it into the path string.

    gNMI list keys live in PathElem.key.  They are not part of PathElem.name,
    so matching only the slash-separated names loses explicit selections such
    as interface[name=eth1] (and the wildcard used by the fleet collector).
    """
    for elem in path.elem:
        if elem.name == element and key in elem.key:
            return elem.key[key]
    return None


def selected_interfaces(path):
    requested = path_elem_key(path, "interface", "name")
    interfaces = metrics.interfaces()
    if requested in (None, "*"):
        return interfaces.items()
    info = interfaces.get(requested)
    return ((requested, info),) if info is not None else ()


def notif_cpu(ts, path=None):
    if path is not None and path_elem_key(path, "cpu", "index") not in (None, "*", CPU_INDEX):
        return []
    n = pb.Notification(timestamp=ts)
    n.update.add(
        path=pb.Path(elem=[pe("system"), pe("cpus"), pe("cpu", index=CPU_INDEX), pe("state"), pe("total"), pe("instant")]),
        val=scalar(int_val=STATE.cpu_percent()),
    )
    return [n]


def notif_memory(ts):
    mem = metrics.memory()
    n = pb.Notification(timestamp=ts, prefix=pb.Path(elem=[pe("system"), pe("memory"), pe("state")]))
    for key in ("physical", "used", "free", "reserved"):
        n.update.add(path=pb.Path(elem=[pe(key)]), val=scalar(uint_val=mem[key]))
    return [n]


def notif_interface_leaf(ts, leaf, path=None):
    out = []
    for name, info in selected_interfaces(path or pb.Path()):
        n = pb.Notification(timestamp=ts)
        n.update.add(
            path=pb.Path(elem=[pe("interfaces"), pe("interface", name=name), pe("state"), pe(leaf)]),
            val=scalar(string_val=info["admin_status"] if leaf == "admin-status" else info["oper_status"]),
        )
        out.append(n)
    return out


def notif_interface_counters(ts, path=None):
    out = []
    for name, info in selected_interfaces(path or pb.Path()):
        if not info["counters"]:
            continue
        n = pb.Notification(timestamp=ts, prefix=pb.Path(elem=[pe("interfaces"), pe("interface", name=name), pe("state"), pe("counters")]))
        for oc_key, value in info["counters"].items():
            n.update.add(path=pb.Path(elem=[pe(oc_key)]), val=scalar(uint_val=value))
        out.append(n)
    return out


PATH_BUILDERS = {
    "system/state/hostname": lambda ts, path: notif_hostname(ts),
    "system/cpus/cpu/state/total/instant": notif_cpu,
    "system/memory/state": lambda ts, path: notif_memory(ts),
    "interfaces/interface/state/oper-status": lambda ts, path: notif_interface_leaf(ts, "oper-status", path),
    "interfaces/interface/state/admin-status": lambda ts, path: notif_interface_leaf(ts, "admin-status", path),
    "interfaces/interface/state/counters": notif_interface_counters,
}


def path_key(path):
    """Collapse a gNMI Path to the same key form used in PATH_BUILDERS,
    dropping key values (wildcards and concrete keys resolve identically)."""
    return "/".join(elem.name for elem in path.elem)


def get_container_json(path):
    """Get()-style single json_ietf_val blob for a container path, matching
    real cEOS Get() behavior (distinct from Subscribe's leaf decomposition)."""
    key = path_key(path)
    if key == "system/memory/state":
        mem = metrics.memory()
        return {f"openconfig-system:{k}": str(v) for k, v in mem.items()}
    if key.startswith("interfaces/interface") and key.endswith("state"):
        iface = path_elem_key(path, "interface", "name")
        info = metrics.interfaces().get(iface)
        if not info:
            return None
        return {
            "openconfig-interfaces:name": iface,
            "openconfig-interfaces:admin-status": info["admin_status"],
            "openconfig-interfaces:oper-status": info["oper_status"],
            "openconfig-interfaces:counters": {f"openconfig-interfaces:{k}": str(v) for k, v in info["counters"].items()},
        }
    return None


class LinuxGnmiServicer(pb_grpc.gNMIServicer):
    def Capabilities(self, request, context):
        check_auth(context)
        models = [
            pb.ModelData(name="openconfig-system", organization="NMAS Linux/FRR telemetry adapter (subset: state/hostname, cpus, memory)", version="0.1.0"),
            pb.ModelData(name="openconfig-interfaces", organization="NMAS Linux/FRR telemetry adapter (subset: state/admin-status, oper-status, counters)", version="0.1.0"),
        ]
        return pb.CapabilityResponse(supported_models=models, supported_encodings=[pb.JSON_IETF], gNMI_version="0.8.0")

    def Get(self, request, context):
        check_auth(context)
        ts = time.time_ns()
        notifications = []
        for path in request.path:
            key = path_key(path)
            if key == "system/state/hostname":
                notifications.extend(notif_hostname(ts))
                continue
            if key == "system/cpus/cpu/state/total/instant":
                notifications.extend(notif_cpu(ts, path))
                continue
            if key == "interfaces/interface/state/oper-status":
                notifications.extend(notif_interface_leaf(ts, "oper-status", path))
                continue
            if key == "interfaces/interface/state/admin-status":
                notifications.extend(notif_interface_leaf(ts, "admin-status", path))
                continue
            if key == "interfaces/interface/state/counters":
                notifications.extend(notif_interface_counters(ts, path))
                continue
            blob = get_container_json(path)
            if blob is not None:
                n = pb.Notification(timestamp=ts)
                n.update.add(path=path, val=scalar(json_ietf_val=json.dumps(blob).encode()))
                notifications.append(n)
        return pb.GetResponse(notification=notifications)

    def Set(self, request, context):
        # Read-only adapter by design -- see module docstring.
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "this adapter is read-only; Set is not implemented")

    def Subscribe(self, request_iterator, context):
        try:
            first = next(request_iterator)
        except StopIteration:
            return
        check_auth(context)
        sub_list = first.subscribe
        if sub_list.mode != pb.SubscriptionList.STREAM:
            context.abort(grpc.StatusCode.UNIMPLEMENTED, "only STREAM subscriptions are implemented")
        subscriptions = []
        interval_ns = 20_000_000_000
        for s in sub_list.subscription:
            if s.mode == pb.ON_CHANGE:
                context.abort(grpc.StatusCode.UNIMPLEMENTED, "ON_CHANGE subscriptions are not implemented")
            k = path_key(s.path)
            if k in PATH_BUILDERS:
                subscriptions.append((k, s.path))
            if s.sample_interval:
                interval_ns = s.sample_interval
        log(f"Subscribe: {len(subscriptions)} path(s), interval={interval_ns / 1e9}s, peer={context.peer()}")
        sent_sync = False
        while context.is_active():
            ts = time.time_ns()
            for key, path in subscriptions:
                for notif in PATH_BUILDERS[key](ts, path):
                    yield pb.SubscribeResponse(update=notif)
            if not sent_sync:
                yield pb.SubscribeResponse(sync_response=True)
                sent_sync = True
            time.sleep(interval_ns / 1e9)


def main():
    address = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 6030
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pb_grpc.add_gNMIServicer_to_server(LinuxGnmiServicer(), server)
    cert_dir = ETC / "tls"
    key = (cert_dir / "server.key").read_bytes()
    cert = (cert_dir / "server.crt").read_bytes()
    creds = grpc.ssl_server_credentials([(key, cert)])
    bound_port = server.add_secure_port(f"{address}:{port}", creds)
    if bound_port != port:
        raise RuntimeError(f"could not bind gNMI adapter to {address}:{port}")
    server.start()
    log(f"listening on {address}:{port} (TLS)")
    server.wait_for_termination()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log(f"FATAL {exc!r}")
        raise
