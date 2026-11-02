#!/usr/bin/env python3
from __future__ import annotations

import ipaddress, json, shlex, subprocess, sys, time
from datetime import datetime
from pathlib import Path

from modules.nmas import NmasError, ensure_nmas_infrastructure, entrypoint

# Bootstrap before third-party imports; --nmas-only exits before Lab 1 runs.
if __name__ == "__main__":
    entrypoint()

from modules.snmp import ensure_snmp_infrastructure
from modules.syslog import ensure_syslog_infrastructure
from modules.telemetry import ensure_telemetry_infrastructure
from modules.grafana import ensure_grafana_infrastructure
from modules.topology import ensure_topology_infrastructure

import yaml
from netmiko import ConnectHandler
from hostserv import bootstrap_linux_ssh, configure_host, configure_webserver, verify_linux
from modules.eos_render import eos_commands, render
from modules.device_credentials import FileSecretProvider, SecretProviderError, ceos_access_profiles, ssh_auth_kwargs
from modules.ipam_context import (
    build_and_validate_nmas_dhcp_context,
    build_and_validate_r2_dhcp_context,
    validate_r2_candidate_render,
)

BASE = Path(__file__).resolve().parent
INV_FILE = BASE / "inventory.yml"
RUN_LOG = BASE / "Run_Logs.log"
LINUX_ROUTERS = {"R3", "R4"}


def log(section, text=""):
    with RUN_LOG.open("a") as f:
        f.write(f"\n[{datetime.now().isoformat(timespec='seconds')}] {section}\n{text}\n")


def run(cmd, check=True, input_data=None):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    p = subprocess.run(cmd, text=True, capture_output=True, input=input_data)
    log("COMMAND", f"$ {' '.join(cmd)}\nRC={p.returncode}\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(cmd)}\n{p.stdout}\n{p.stderr}")
    return p


def docker(args, check=True, input_data=None):
    for cmd in (["docker", *args], ["sudo", "docker", *args]):
        p = run(cmd, False, input_data)
        if p.returncode == 0:
            return p
        msg = ((p.stdout or "") + (p.stderr or "")).lower()
        if "permission denied" not in msg and "cannot connect" not in msg:
            break
    if check:
        raise RuntimeError((p.stdout or "") + (p.stderr or ""))
    return p


def load_inventory():
    with INV_FILE.open() as f:
        return yaml.safe_load(f)


def discover_ip(lab, node):
    data = json.loads(docker(["inspect", f"clab-{lab}-{node}"]).stdout)[0]
    ips = [n["IPAddress"] for n in data["NetworkSettings"]["Networks"].values() if n.get("IPAddress")]
    if not ips:
        raise RuntimeError(f"No management IP for {node}")
    preferred = ipaddress.ip_network("172.20.20.0/24")
    for ip in ips:
        if ipaddress.ip_address(ip) in preferred:
            return ip
    return ips[0]


def eos_conn(node, ip, inv, session_log=None):
    last_error = None
    for access in ceos_access_profiles(inv, node):
        # An enrolled key must load or the device-specific session fails
        # closed. There is deliberately no fleet-wide rollback identity.
        auth = ssh_auth_kwargs(access.ssh_key_ref)
        try:
            materials = FileSecretProvider().candidates(access.credential_ref)
        except SecretProviderError as exc:  # sanitized below
            last_error = exc
            continue
        for material in materials:
            try:
                return ConnectHandler(
                    device_type="arista_eos", host=ip,
                    username=access.username, password=material.value,
                    secret=material.value,
                    fast_cli=False, session_log=str(session_log) if session_log else None,
                    conn_timeout=20, auth_timeout=20, banner_timeout=30, **auth,
                )
            except Exception as exc:  # sanitized by the caller; try recovery candidates
                last_error = exc
    raise RuntimeError("Device authentication failed for every protected credential candidate") from last_error


def _build_eos_config(node, inv):
    """Render one EOS device's desired configuration text. Thin by design
    (Step 4): the only DHCP-specific logic here is the one-line decision
    to attach R2's context -- building it, validating pool safety, and
    validating the render are all `modules.ipam_context` responsibilities.
    A NetBox/pool-safety failure here raises and aborts BEFORE `push_eos()`
    connects to R2 at all (Step 7's fail-closed contract) -- it never
    falls back to rendering R2 without its DHCP section."""
    meta = inv["network_devices"][node]
    context = {"management": inv["management"], "node": node}
    if node == "R2":
        context["dhcp"] = build_and_validate_r2_dhcp_context()
    cfg = render(f"templates/{meta['template']}", context)
    if node == "R2":
        validate_r2_candidate_render(cfg)
    return cfg


def push_eos(node, ip, inv):
    cfg = _build_eos_config(node, inv)
    print(f"{node}: configuring...", flush=True)
    if (inv["network_devices"].get(node) or {}).get("edge"):
        # R5 is deliberately outside NMAS managed credential scope. Bootstrap
        # it only through the trusted host-side console; never restore the
        # retired fleet credential as an SSH fallback.
        commands = ["enable", "configure terminal", *eos_commands(cfg), "end", "write memory"]
        result = docker(
            ["exec", "-i", f"clab-{inv['lab_name']}-{node}", "Cli", "-p", "15"],
            input_data="\n".join(commands) + "\n",
        )
        errors = ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Error")
        if any(marker in result.stdout for marker in errors):
            raise RuntimeError(f"{node}: console configuration rejected")
        log(f"CONSOLE CONFIG {node}", result.stdout)
        print(f"{node}: configuration OK")
        return
    logdir = BASE / "logs"
    logdir.mkdir(exist_ok=True)
    conn = eos_conn(node, ip, inv, logdir / f"{node}.log")
    try:
        if not conn.check_enable_mode():
            conn.enable()
        conn.config_mode(config_command="configure terminal", pattern=r"\(config[^\)]*\)#")
        time.sleep(1)
        output = conn.send_config_set(
            eos_commands(cfg), enter_config_mode=False, exit_config_mode=False,
            cmd_verify=True, read_timeout=120,
        )
        log(f"CONFIG {node}", output)
        errors = ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Error")
        if any(e in output for e in errors):
            raise RuntimeError(f"{node}: config rejected; see logs/{node}.log and Run_Logs.log")
        while conn.check_config_mode():
            conn.exit_config_mode()
        log(f"WRITE MEMORY {node}", conn.send_command_timing("write memory"))
        print(f"{node}: configuration OK")
    finally:
        conn.disconnect()


def linux_exec(lab, node, command, stdin_data=None):
    """Run one Linux command through the trusted host-side container console."""
    name = f"clab-{lab}-{node}"
    result = docker(["exec", "-i", name, "bash", "-lc", command], input_data=stdin_data)
    log(f"CONSOLE {node}", f"RC={result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    return result.stdout

def push_linux_router(node, ip, inv):
    meta = inv["network_devices"][node]
    cfg = render(
        f"templates/{meta['template']}",
        {"management": inv["management"], "node": node},
    )

    print(f"{node}: configuring Ubuntu/FRR/NAT via container console...", flush=True)

    remote = f"/tmp/{node}.cfg"

    linux_exec(
        inv["lab_name"], node,
        f"cat > {remote}",
        stdin_data=cfg,
    )

    syntax = linux_exec(
        inv["lab_name"], node,
        f"bash -n {remote}",
    )

    if syntax.strip():
        log(f"SYNTAX {node}", syntax)

    output = linux_exec(
        inv["lab_name"], node,
        f"bash {remote}",
    )

    log(f"CONFIG {node}", output)
    print(f"{node}: configuration OK")

def setup_nmas(inv):
    mgmt = inv["management"]
    iface = mgmt["host_interface"]
    print("NMAS: configuring management/DHCP...")
    run(["sudo", "ip", "link", "set", iface, "up"])
    run(["sudo", "ip", "addr", "replace", mgmt["nmas_ipv4"], "dev", iface])
    run(["sudo", "ip", "-6", "addr", "replace", mgmt["nmas_ipv6"], "dev", iface])

    for net in ("192.168.10.0/24", "192.168.20.0/24"):
        run(["sudo", "ip", "route", "del", net, "dev", iface], False)
    for net in ("2001:db8:10::/64", "2001:db8:20::/64", "2001:db8:30::/64"):
        run(["sudo", "ip", "-6", "route", "del", net, "dev", iface], False)

    relay4 = {
        "192.168.10.2/32": "192.168.200.11",
        "192.168.20.2/32": "192.168.200.11",
        "192.168.10.3/32": "192.168.200.12",
        "192.168.20.3/32": "192.168.200.12",
    }
    relay6 = {
        "2001:db8:10::2/128": "2001:db8:200::11",
        "2001:db8:20::2/128": "2001:db8:200::11",
        "2001:db8:30::2/128": "2001:db8:200::11",
        "2001:db8:10::3/128": "2001:db8:200::12",
        "2001:db8:20::3/128": "2001:db8:200::12",
        "2001:db8:30::3/128": "2001:db8:200::12",
    }

    for dst, via in relay4.items():
        run(["sudo", "ip", "route", "replace", dst, "via", via, "dev", iface])
    for dst, via in relay6.items():
        run(["sudo", "ip", "-6", "route", "replace", dst, "via", via, "dev", iface])

    if not inv["toggles"].get("configure_nmas_dhcp", True):
        print("NMAS: management OK")
        return

    # Phase 3G: the primary pool boundaries are NetBox-derived (Step 17/18)
    # -- this call raises on any NetBox/pool-safety failure, BEFORE
    # apt-get, BEFORE any file is written, and BEFORE any service is
    # touched. There is no fallback to a hard-coded range here.
    dhcp = build_and_validate_nmas_dhcp_context()

    run(["sudo", "apt-get", "update"])
    run(["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "isc-dhcp-server"])
    Path("/tmp/clab-dhcpd.conf").write_text(render("dhcp/dhcpd.conf.j2", {"management": mgmt, "dhcp": dhcp}))
    Path("/tmp/clab-dhcpd6.conf").write_text(render("dhcp/dhcpd6.conf.j2", {"management": mgmt, "dhcp": dhcp}))
    Path("/tmp/clab-dhcp-defaults").write_text(f'INTERFACESv4="{iface}"\nINTERFACESv6="{iface}"\n')

    for src, dst in [
        ("/tmp/clab-dhcpd.conf", "/etc/dhcp/dhcpd.conf"),
        ("/tmp/clab-dhcpd6.conf", "/etc/dhcp/dhcpd6.conf"),
        ("/tmp/clab-dhcp-defaults", "/etc/default/isc-dhcp-server"),
    ]:
        run(["sudo", "cp", src, dst])

    run(["sudo", "dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"])
    run(["sudo", "dhcpd", "-6", "-t", "-cf", "/etc/dhcp/dhcpd6.conf"])
    run(["sudo", "systemctl", "restart", "isc-dhcp-server"], False)
    run(["sudo", "systemctl", "restart", "isc-dhcp-server6"], False)
    print("NMAS: configuration OK")


def verify_eos(node, ip, inv):
    edge_console = bool(((inv.get("network_devices") or {}).get(node) or {}).get("edge"))
    conn = None if edge_console else eos_conn(node, ip, inv)
    failed = []
    try:
        if conn is not None and not conn.check_enable_mode():
            conn.enable()
        cmds = ["show ip interface brief", "show ipv6 interface brief"]
        if node in {"R1", "R2"}:
            cmds += ["show ip route rip", "show ip ospf neighbor", "show ipv6 ospf neighbor", "show nexthop-group"]
        elif node in {"S1", "S2"}:
            cmds += ["show ip route rip", "show nexthop-group"]
        elif node == "R5":
            cmds += ["show ip bgp summary", "show ipv6 bgp summary"]

        outputs = {}
        for cmd in cmds:
            if edge_console:
                outputs[cmd] = docker([
                    "exec", f"clab-{inv['lab_name']}-{node}", "Cli", "-p", "15", "-c", cmd,
                ]).stdout
            else:
                outputs[cmd] = conn.send_command(cmd, read_timeout=30)
            log(f"{node}# {cmd}", outputs[cmd])

        if node in {"R1", "R2"}:
            if not outputs.get("show ip ospf neighbor", "").strip().splitlines()[1:]:
                failed.append("OSPFv2 has no neighbors")
            if not outputs.get("show ipv6 ospf neighbor", "").strip():
                failed.append("OSPFv3 has no neighbors")
        if node in {"S1", "S2", "R1", "R2"}:
            nh = outputs.get("show nexthop-group", "")
            if "(drop)" in nh or "Unprogrammed nexthop group" in nh:
                failed.append("IPIP nexthop-group unresolved")
        if node == "R5":
            for af in ("show ip bgp summary", "show ipv6 bgp summary"):
                if "Estab" not in outputs.get(af, ""):
                    failed.append(f"{af} has no established peer")
    except Exception as e:
        failed.append(str(e))
        log(f"VERIFY ERROR {node}", str(e))
    finally:
        if conn is not None:
            conn.disconnect()

    if failed:
        print(f"{node}: verification FAILED - see Run_Logs.log")
        log(f"VERIFY RESULT {node}", "FAILED: " + "; ".join(failed))
        return False
    print(f"{node}: verification OK")
    log(f"VERIFY RESULT {node}", "OK")
    return True


def verify_linux_router(node, inv):
    cmd = """ip -br addr
echo '--- bridges ---'; bridge link
echo '--- routes ---'; ip route; ip -6 route
echo '--- OSPFv2 ---'; vtysh -c 'show ip ospf neighbor' || true
echo '--- OSPFv3 ---'; vtysh -c 'show ipv6 ospf6 neighbor' || true
echo '--- BGPv4 ESTABLISHED ---'; vtysh -c 'show bgp ipv4 unicast summary established' || true
echo '--- BGPv6 ESTABLISHED ---'; vtysh -c 'show bgp ipv6 unicast summary established' || true
echo '--- NAT ---'; nft list table ip EDGE_PAT || true"""
    try:
        output = linux_exec(inv["lab_name"], node, cmd)
        log(f"VERIFY {node}", output)
        failed = []

        if "EDGE_PAT" not in output:
            failed.append("NAT/PAT table missing")

        print(f"{node}: verification {'FAILED' if failed else 'OK'}")
        if failed:
            log(f"VERIFY RESULT {node}", "FAILED: " + "; ".join(failed))
            return False

        log(f"VERIFY RESULT {node}", "OK")
        return True

    except Exception as e:
        print(f"{node}: verification FAILED - see Run_Logs.log")
        log(f"VERIFY ERROR {node}", str(e))
        return False


def main():
    RUN_LOG.write_text("")
    inv = load_inventory()
    lab, toggles = inv["lab_name"], inv["toggles"]
    setup_nmas(inv)

    net_nodes = [
        n for n, m in inv["network_devices"].items()
        if not (m.get("edge") and not toggles.get("include_r5", True))
    ]
    linux_nodes = list(inv["hosts"]) if toggles.get("configure_hosts", True) else []
    if toggles.get("include_webserver", True):
        linux_nodes.append("WebServer")

    ips = {n: discover_ip(lab, n) for n in net_nodes + linux_nodes}
    log("MANAGEMENT IPS", "\n".join(f"{n}: {ip}" for n, ip in ips.items()))

    order = ["mgmt_swt", "S3", "S4", "S1", "S2", "R1", "R2", "R3", "R4"]
    if toggles.get("include_r5", True):
        order.append("R5")

    for node in ("R3", "R4"):
        if node in ips:
            print(f"{node}: enabling SSH...")
            bootstrap_linux_ssh(lab, node, docker, log)
            time.sleep(1)

    for node in order:
        if node not in ips:
            continue
        if node in LINUX_ROUTERS:
            push_linux_router(node, ips[node], inv)
        else:
            push_eos(node, ips[node], inv)

    for node in linux_nodes:
        bootstrap_linux_ssh(lab, node, docker, log)

    if toggles.get("include_webserver", True):
        configure_webserver(lab, "WebServer", docker, log)

    if toggles.get("configure_hosts", True):
        for node, meta in inv["hosts"].items():
            configure_host(lab, node, docker, meta["ipv4"], meta["ipv6"], log)

    ensure_nmas_infrastructure(verbose="--verbose" in sys.argv, prepared=True)
    ensure_snmp_infrastructure(verbose="--verbose" in sys.argv)
    ensure_syslog_infrastructure(verbose="--verbose" in sys.argv)
    ensure_telemetry_infrastructure(verbose="--verbose" in sys.argv)
    ensure_grafana_infrastructure(verbose="--verbose" in sys.argv)
    ensure_topology_infrastructure(verbose="--verbose" in sys.argv)

    print("\nVerification:")
    for node in order:
        if node not in ips:
            continue
        if node in LINUX_ROUTERS:
            verify_linux_router(node, inv)
        else:
            verify_eos(node, ips[node], inv)

    if toggles.get("configure_hosts", True):
        for node in inv["hosts"]:
            verify_linux(lab, node, docker, log)

    subprocess.run(["python3", str(BASE / "address_report.py")], check=False)

    print(f"\nDetailed output: {RUN_LOG}")


if __name__ == "__main__":
    try:
        main()
    except NmasError as exc:
        raise SystemExit(f"[ NMAS ] FAIL: {exc}") from exc
