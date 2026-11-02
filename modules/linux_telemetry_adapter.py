"""Idempotent deployment of the lab telemetry adapters to Ubuntu/FRR R3/R4.

The adapters expose real Linux state through genuine gNMI-over-TLS and
NETCONF-over-SSH protocols.  They are explicitly an NMAS lab adapter, not a
claim of native FRR support, and never touch routing or interface state.
"""
from __future__ import annotations

import json
from pathlib import Path

import pygnmi

from modules.nmas import MONITORING, NmasError
from modules.snmp import docker


ADAPTER_FILES = (
    "linux_gnmi_server.py",
    "linux_netconf_server.py",
    "nmas_linux_telemetry_metrics.py",
)
PROTO_FILES = ("gnmi_pb2.py", "gnmi_pb2_grpc.py", "gnmi_ext_pb2.py")


def protobuf_sources():
    spec_dir = Path(pygnmi.__file__).resolve().parent / "spec" / "v080"
    result = {}
    for name in PROTO_FILES:
        path = spec_dir / name
        if not path.is_file():
            raise NmasError("pygnmi protobuf source missing: " + str(path))
        # pygnmi ships these as package modules.  The router intentionally
        # receives only the generated stubs (not the client package), so make
        # their two sibling imports local while preserving generated code.
        result[name] = (
            path.read_text()
            .replace("import pygnmi.spec.v080.gnmi_ext_pb2 as gnmi__ext__pb2", "import gnmi_ext_pb2 as gnmi__ext__pb2")
            .replace("import pygnmi.spec.v080.gnmi_pb2 as gnmi__pb2", "import gnmi_pb2 as gnmi__pb2")
        )
    return result


def configure(item, username, password):
    files = {
        name: (MONITORING / "scripts" / name).read_text()
        for name in ADAPTER_FILES
    }
    files.update(protobuf_sources())
    payload = {
        "device": item["device"],
        "address": item["address"],
        "username": username,
        "password": password,
        "files": files,
    }
    provisioner = (MONITORING / "scripts/provision_linux_telemetry.py").read_text()
    result = docker(
        "exec", "-i", item["container"], "python3", "-c", provisioner,
        data=json.dumps(payload), timeout=900,
    )
    print(item["device"] + ": " + result.strip(), flush=True)


def fetch_certificate(item, destination):
    text = docker(
        "exec", item["container"], "cat", "/etc/nmas-telemetry/tls/server.crt"
    )
    if "BEGIN CERTIFICATE" not in text:
        raise NmasError(item["device"] + ": telemetry adapter certificate missing")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists() or destination.read_text() != text:
        destination.write_text(text)
    destination.chmod(0o644)
    return destination
