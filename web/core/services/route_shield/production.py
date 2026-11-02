"""The production wiring of the baseline migration: the six managed devices, their executors, and the probe flows.

Nothing here runs on import.  ``environment()`` opens no connection (the lifecycle connects), and the probe flows are
only started by the caller.  The client hosts and the service are read from ``inventory.yml``; a host's own address is
read from the host at that moment (read-only), because it is assigned by DHCP.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess

from ..execution.executors.ceos import CeosExecutor
from ..health import inventory, live
from . import core_cover, gates, lab, lifecycle, migration, probes

SERVICE_V4, SERVICE_V6, SERVICE_HOST = "172.30.50.10", migration.PRODUCTION.service, "WebServer"
CLIENT_V4 = ("192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24")


def devices() -> dict:
    managed = inventory.managed_devices()
    return {name: managed[name] for name in migration.PRODUCTION.devices if name in managed}


def executor_for(device: dict):
    """R3/R4 get the kernel-cover executor and nothing else; the access devices get the cEOS executor.  The cover
    executor is built without a sandbox inventory: it can only ever send ``core_cover.APPROVED_COVERS``."""
    if device["name"] in migration.PRODUCTION.cores:
        return core_cover.KernelCoverExecutor(device)
    return CeosExecutor(device)


def _container(name: str) -> str:
    lab_name = inventory.load_inventory().get("lab_name", "")
    return f"clab-{lab_name}-{name}"


def host_addresses(container: str) -> list[str]:
    """The client-VLAN addresses a host holds right now (read-only ``ip -j addr show``)."""
    done = subprocess.run(["docker", "exec", container, "ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=20, check=False)  # noqa: S603
    wanted = [ipaddress.ip_network(p) for p in (*CLIENT_V4, *lab.CLIENTS)]
    found = []
    for row in json.loads(done.stdout or "[]") if done.returncode == 0 else []:
        for entry in row.get("addr_info") or []:
            try:
                address = ipaddress.ip_address(entry.get("local"))
            except ValueError:
                continue
            if any(address in network for network in wanted) and not entry.get("deprecated"):
                found.append(str(address))
    return sorted(found)


def flows(read_addresses=host_addresses) -> list[probes.Flow]:
    """Every healthy applicable client: H1 to H4 toward the service in each family the host has, and the service back to
    each host address.  Re-read immediately before a window: a host that holds no address simply has no flow, and the
    precheck then reports which hosts are covered."""
    hosts = inventory.load_inventory().get("hosts") or {}
    found = []
    for name, families in sorted(hosts.items()):
        label, container = name.lower(), _container(name)
        if families.get("ipv6"):
            found.append(probes.Flow(f"{label}-service-v6", container, SERVICE_V6, 0.01))
        if families.get("ipv4"):
            found.append(probes.Flow(f"{label}-service-v4", container, SERVICE_V4, 0.1))
        for address in read_addresses(container):
            six = ipaddress.ip_address(address).version == 6
            found.append(probes.Flow(f"service-{label}-v{6 if six else 4}-{len(found)}", _container(SERVICE_HOST), address, 0.02 if six else 0.1,
                                     SERVICE_V6 if six else SERVICE_V4))
    return found


def environment(probe_source=None) -> lifecycle.Environment:
    return lifecycle.Environment(devices=devices(), executor_factory=executor_for, read=live.read_device,
                                 probes=probe_source if probe_source is not None else probes.HostProbes(flows()), host_gate=gates.WindowGate())


def start_probes(env) -> None:
    """The quiet-host gate is measured first: once the probes run, the host is no longer quiet by their own doing."""
    measure = getattr(env.host_gate, "measure_quiet", None)
    if measure is not None:
        measure()
    env.probes.start()
