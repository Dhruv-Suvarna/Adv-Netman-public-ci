#!/usr/bin/env python3

import csv
import ipaddress
import json
import re
import subprocess
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parent
CSV_FILE = BASE / "address_report.csv"
LINUX_NODES = {"R3", "R4", "H1", "H2", "H3", "H4", "WebServer"}


def docker_inspect(name):
    for cmd in (["docker", "inspect", name], ["sudo", "docker", "inspect", name]):
        p = subprocess.run(cmd, text=True, capture_output=True)
        if p.returncode == 0:
            return json.loads(p.stdout)[0]
    raise RuntimeError(f"Cannot inspect {name}")


def management_ip(lab, node):
    data = docker_inspect(f"clab-{lab}-{node}")
    ips = [
        n.get("IPAddress")
        for n in data["NetworkSettings"]["Networks"].values()
        if n.get("IPAddress")
    ]
    preferred = ipaddress.ip_network("172.20.20.0/24")
    for ip in ips:
        if ipaddress.ip_address(ip) in preferred:
            return ip
    if ips:
        return ips[0]
    raise RuntimeError(f"No Containerlab management IP for {node}")


def docker_exec(name, argv):
    for command in (["docker", "exec", name, *argv], ["sudo", "docker", "exec", name, *argv]):
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode == 0:
            return result.stdout
    raise RuntimeError(f"Container console command failed for {name}")


def linux_addresses(lab, node):
    out = docker_exec(f"clab-{lab}-{node}", ["bash", "-lc", "ip -o -4 addr show; ip -o -6 addr show"])
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+(\S+)\s+inet(6?)\s+(\S+)", line)
        if not m:
            continue
        iface = m.group(1).split("@")[0]
        family = "IPv6" if m.group(2) else "IPv4"
        rows.append((iface, family, m.group(3)))
    return rows


def linux_leases(lab, node):
    out = docker_exec(
        f"clab-{lab}-{node}", ["bash", "-lc",
        "cat /var/lib/dhcp/dhclient*.leases 2>/dev/null || true; "
        "cat /tmp/dhclient4.log 2>/dev/null || true; "
        "cat /tmp/dhclient6.log 2>/dev/null || true"],
    )
    leases = {}

    for block in re.findall(r"lease\s*\{.*?\n\}", out, re.S):
        addr = re.search(r"fixed-address\s+([^;]+);", block)
        if not addr:
            continue
        expiry = re.search(r"expire\s+\d+\s+([^;]+);", block)
        leases[addr.group(1).strip()] = (
            f"DHCPv4 expire {expiry.group(1).strip()}" if expiry else "DHCPv4"
        )

    for addr, body in re.findall(r"iaaddr\s+([^\s{]+)\s*\{(.*?)\}", out, re.S):
        life = re.search(r"max-life\s+(\d+);", body)
        leases[addr.strip()] = (
            f"DHCPv6 max-life {life.group(1)}s" if life else "DHCPv6"
        )

    for addr, seconds in re.findall(r"bound to\s+(\d+\.\d+\.\d+\.\d+)\s+-- renewal in\s+(\d+)\s+seconds", out):
        leases.setdefault(addr, f"DHCPv4 renewal {seconds}s")

    for addr in re.findall(r"Confirm Address\s+([0-9A-Fa-f:]+)", out):
        leases.setdefault(addr, "DHCPv6")

    return leases


def eos_addresses(lab, node):
    name = f"clab-{lab}-{node}"
    v4 = docker_exec(name, ["Cli", "-p", "15", "-c", "show ip interface brief"])
    v6 = docker_exec(name, ["Cli", "-p", "15", "-c", "show ipv6 interface brief"])

    rows = []
    current_iface = None

    for line in v4.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+/\d+", parts[1]):
            rows.append((parts[0], "IPv4", parts[1]))

    for line in v6.splitlines():
        parts = line.split()
        if not parts:
            continue
        addrs = [p for p in parts if ":" in p and "/" in p]
        if not addrs:
            continue
        if ":" not in parts[0] and "/" not in parts[0]:
            current_iface = parts[0]
        if current_iface:
            for addr in addrs:
                rows.append((current_iface, "IPv6", addr))

    return rows


def print_table(rows):
    headers = ["Device", "Interface", "Family", "Address", "DHCP Lease"]
    data = [headers] + rows
    widths = [max(len(str(r[i])) for r in data) for i in range(len(headers))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for row in rows:
        print(fmt.format(*row))


def main():
    with (BASE / "inventory.yml").open() as f:
        inv = yaml.safe_load(f)

    lab = inv["lab_name"]
    nodes = list(inv["network_devices"])
    if inv["toggles"].get("configure_hosts", True):
        nodes += list(inv["hosts"])
    if inv["toggles"].get("include_webserver", True):
        nodes.append("WebServer")

    rows = []
    for node in nodes:
        leases = linux_leases(lab, node) if node in LINUX_NODES else {}
        addresses = linux_addresses(lab, node) if node in LINUX_NODES else eos_addresses(lab, node)
        for iface, family, address in addresses:
            host = address.split("/")[0]
            rows.append([node, iface, family, address, leases.get(host, "")])

    rows.sort(key=lambda r: (r[0], r[1], r[2], r[3]))

    with CSV_FILE.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["device", "interface", "family", "address", "dhcp_lease"])
        writer.writerows(rows)

    print(f"\nAddress/DHCP report: {CSV_FILE}\n")
    print_table(rows)


if __name__ == "__main__":
    main()
