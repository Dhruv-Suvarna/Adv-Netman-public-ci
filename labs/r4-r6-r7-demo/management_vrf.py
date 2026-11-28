#!/usr/bin/env python3
"""Multi-hop Management VRF for the R4 -> R6 -> R7 lab segment (Infrastructure-as-Code: apply / confirm / verify / rollback).

    NMAS nmas-mgmt 192.168.200.100 --VLAN 200--> R4 Vlan200 192.168.200.4        (the approved NMA-000001 attachment + R4's path)
    R4  eth4.251   10.254.251.1/30  [Linux VRF MGMT, table 251]  <-- 802.1Q 251 on the verified R4 eth4 <-> R6 Ethernet1 link
    R6  Ethernet1.251 10.254.251.2/30 [vrf MGMT]                  endpoint of R6's ROUTED_VRF path
    R6  Ethernet2.251 10.254.251.5/30 [vrf MGMT]  <-- 802.1Q 251 on the verified R6 Ethernet2 <-> R7 Ethernet1 link
    R7  Ethernet1.251 10.254.251.6/30 [vrf MGMT]                  endpoint of R7's ROUTED_VRF path

VLAN 200 is never stretched over a routed link: the VRF rides tagged subinterfaces of the existing routed links, so no cable,
link or production address changes.  Isolation:

* R4 leaks ONLY ``iif Vlan200 from 192.168.200.100 to 10.254.251.0/29`` into table 251 (policy rule), and table 251 returns
  only to 192.168.200.100; nothing is redistributed into OSPF/BGP and production sources never enter the VRF;
* R6/R7 hold the VRF on subinterfaces only, with a /32 return route to the NMAS source via the attachment's neighbour, and
  ``management ssh`` in the VRF restricted by an ACL to the NMAS source.

EOS changes go through a ``configure session`` committed with ``commit timer``: unless ``confirm`` follows within the timer, EOS
restores the previous configuration by itself (automatic rollback).  No command output that could carry configuration secrets is
printed: only parsed facts.  Not a management path by itself -- NMAS registers and probes the paths (``nmas_management``).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys

VID, TABLE, VRF = 251, 251, "MGMT"
NMAS_SOURCE, NMAS_IF, GATEWAY_V200 = "192.168.200.100", "nmas-mgmt", "192.168.200.4"
PREFIX = "10.254.251.0/29"
R4 = {"container": "clab-srlceos01-R4", "parent": "eth4", "address": "10.254.251.1/30", "svi": "Vlan200"}
EOS = {
    "R6": {"container": "nmas-demo-r6", "subs": [("Ethernet1", "10.254.251.2/30", "NMAS management VRF uplink (R4 eth4.251)"),
                                                 ("Ethernet2", "10.254.251.5/30", "NMAS management VRF to R7")],
           "return_hop": "10.254.251.1", "routes": [], "endpoint": "10.254.251.2"},
    "R7": {"container": "nmas-demo-r7", "subs": [("Ethernet1", "10.254.251.6/30", "NMAS management VRF uplink (R6 Ethernet2.251)")],
           "return_hop": "10.254.251.5", "routes": [], "endpoint": "10.254.251.6"},
}
R4_ROUTES = [("10.254.251.4/30", "via 10.254.251.2 dev eth4.251"), (f"{NMAS_SOURCE}/32", f"dev {R4['svi']}")]
RULE = f"pref 900 iif {R4['svi']} from {NMAS_SOURCE}/32 to {PREFIX} lookup {TABLE}"
SESSION, ACL, TIMER = "nmas-mgmt-vrf", "NMAS-MGMT-VRF", "00:10:00"

# Bootstrap relay networks (NMAS BootstrapNetwork demo-r6-ztp-2 / demo-r7-ztp-2; DHCPv4 only -- DHCPv6 stays unsupported).
# The NMAS dhcpd matches each ZTP class on giaddr, so the relay must SEND the bootstrap gateway as giaddr:
#  * R6 (EOS) relays for R7 from a secondary address with ``ip dhcp relay all-subnets`` (one relayed copy per subnet);
#  * R4's ISC dhcrelay always uses eth4's FIRST address as giaddr.  The secondary is added now (additive); the giaddr only
#    becomes 10.254.98.1 when R6's production 10.254.90.1/29 is re-added after it, which happens inside R6's re-bootstrap
#    window (``relay-window R4``), never while R6 carries production traffic.
RELAY_SESSION = "nmas-bootstrap-relay"   # EOS session names are single-use: one per change
RELAY = {"R4": {"interface": "eth4", "gateway": "10.254.98.1/29"},
         "R6": {"interface": "Ethernet2", "gateway": "10.254.99.1/29", "helper": "10.254.92.2"}}


def run(argv, *, input_text=None, check=True) -> str:
    result = subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=60)
    if check and result.returncode:
        raise SystemExit(f"FAILED rc={result.returncode}: {' '.join(argv[:4])} ...")
    return result.stdout


def r4(cmd: str, check=True) -> str:
    return run(["docker", "exec", R4["container"], "sh", "-c", cmd], check=check)


def eos(device: str, command: str) -> str:
    return run(["docker", "exec", EOS[device]["container"], "Cli", "-p", "15", "-c", command])


def eos_session(device: str, lines: list[str], session: str = SESSION) -> list[str]:
    """Feed one configure session on stdin; -> the CLI error lines (``%``)."""
    # ``commit timer`` leaves configuration mode, so no trailing ``end`` (it would only report "% Invalid input")
    script = "\n".join([f"configure session {session}", *lines, f"commit timer {TIMER}", ""])
    out = run(["docker", "exec", "-i", EOS[device]["container"], "Cli", "-p", "15"], input_text=script, check=False)
    return [line.strip() for line in out.splitlines() if line.lstrip().startswith("%")]


def eos_lines(device: str) -> list[str]:
    spec = EOS[device]
    lines = [f"vrf instance {VRF}", "   description NMAS management VRF", f"ip routing vrf {VRF}",
             f"ip access-list {ACL}", f"   10 permit tcp host {NMAS_SOURCE} any eq ssh"]
    for parent, cidr, description in spec["subs"]:
        lines += [f"interface {parent}.{VID}", f"   description {description}", f"   encapsulation dot1q vlan {VID}",
                  f"   vrf {VRF}", f"   ip address {cidr}"]
    lines += [f"ip route vrf {VRF} {NMAS_SOURCE}/32 {spec['return_hop']}"]
    lines += ["management ssh", f"   ip access-group {ACL} vrf {VRF} in", f"   vrf {VRF}", "      no shutdown"]
    return lines


def eos_rollback_lines(device: str) -> list[str]:
    spec = EOS[device]
    return (["management ssh", f"   no vrf {VRF}", f"   no ip access-group {ACL} vrf {VRF} in", "exit",
             f"no ip route vrf {VRF} {NMAS_SOURCE}/32 {spec['return_hop']}"]
            + [f"no interface {parent}.{VID}" for parent, _cidr, _d in spec["subs"]]
            + [f"no ip access-list {ACL}", f"no ip routing vrf {VRF}", f"no vrf instance {VRF}"])


# --- apply / confirm / rollback ----------------------------------------------------------------------------------------------
def apply_r4() -> None:
    sub = f"{R4['parent']}.{VID}"
    r4(f"ip link show {VRF} >/dev/null 2>&1 || ip link add {VRF} type vrf table {TABLE}; ip link set {VRF} up; "
       f"ip link show {sub} >/dev/null 2>&1 || ip link add link {R4['parent']} name {sub} type vlan id {VID}; "
       f"ip link set {sub} master {VRF}; ip link set {sub} up; ip addr replace {R4['address']} dev {sub}; "
       f"sysctl -qw net.ipv4.conf.{sub.replace('.', '/')}.rp_filter=0")
    for prefix, nexthop in R4_ROUTES:
        r4(f"ip route replace table {TABLE} {prefix} {nexthop}")
    r4(f"ip rule show pref 900 | grep -q 'lookup {TABLE}' || ip rule add {RULE}")


def rollback_r4() -> None:
    r4(f"ip rule del pref 900 2>/dev/null; ip link del {R4['parent']}.{VID} 2>/dev/null; ip link del {VRF} 2>/dev/null; true", check=False)


def apply_host() -> None:
    run(["sudo", "-n", "ip", "route", "replace", PREFIX, "via", GATEWAY_V200, "dev", NMAS_IF, "src", NMAS_SOURCE])


def rollback_host() -> None:
    run(["sudo", "-n", "ip", "route", "del", PREFIX, "via", GATEWAY_V200, "dev", NMAS_IF], check=False)


def apply_eos(device: str) -> dict:
    errors = eos_session(device, eos_lines(device))
    return {"device": device, "cli_errors": errors, "pending_confirm_within": TIMER if not errors else ""}


def confirm_eos(device: str, session: str = SESSION) -> dict:
    out = run(["docker", "exec", "-i", EOS[device]["container"], "Cli", "-p", "15"],
              input_text=f"configure session {session} commit\n", check=False)
    return {"device": device, "cli_errors": [line.strip() for line in out.splitlines() if line.lstrip().startswith("%")]}


def rollback_eos(device: str) -> dict:
    script = "\n".join(["configure session nmas-mgmt-vrf-rollback", *eos_rollback_lines(device), "commit", ""])
    out = run(["docker", "exec", "-i", EOS[device]["container"], "Cli", "-p", "15"], input_text=script, check=False)
    return {"device": device, "cli_errors": [line.strip() for line in out.splitlines() if line.lstrip().startswith("%")]}


def apply_relay(target: str) -> dict:
    spec = RELAY[target]
    if target == "R4":
        r4(f"ip addr show dev {spec['interface']} | grep -q ' {spec['gateway']} ' || ip addr add {spec['gateway']} dev {spec['interface']}")
        return verify_relay("R4")
    lines = [f"interface {spec['interface']}", f"   ip address {spec['gateway']} secondary", "   ip dhcp relay all-subnets"]
    errors = eos_session(target, lines, RELAY_SESSION)
    return {"device": target, "session": RELAY_SESSION, "cli_errors": errors, "pending_confirm_within": "" if errors else TIMER}


def rollback_relay(target: str) -> dict:
    spec = RELAY[target]
    if target == "R4":
        r4(f"ip addr del {spec['gateway']} dev {spec['interface']} 2>/dev/null; true", check=False)
        return verify_relay("R4")
    script = "\n".join(["configure session nmas-relay-rollback", f"interface {spec['interface']}",
                        "   no ip dhcp relay all-subnets", f"   no ip address {spec['gateway']} secondary", "commit", ""])
    out = run(["docker", "exec", "-i", EOS[target]["container"], "Cli", "-p", "15"], input_text=script, check=False)
    return {"device": target, "cli_errors": [line.strip() for line in out.splitlines() if line.lstrip().startswith("%")]}


def relay_window_r4(*, restore: bool) -> dict:
    """INSIDE R6's re-bootstrap window only: re-add 10.254.90.1/29 after the bootstrap gateway so dhcrelay's giaddr is
    10.254.98.1 (``restore``: the reverse, so 10.254.90.1 is first again), then restart dhcrelay with its own argv."""
    first, second = ("10.254.90.1/29", "10.254.98.1/29") if restore else ("10.254.98.1/29", "10.254.90.1/29")
    r4(f"ip addr del {second} dev eth4 2>/dev/null; ip addr add {second} dev eth4; "
       f"ip addr show dev eth4 | grep -q ' {first} ' || ip addr add {first} dev eth4")
    restart_dhcrelay()
    return verify_relay("R4")


def restart_dhcrelay() -> None:
    """Restart R4's dhcrelay with its exact running argv (it reads interface addresses, hence giaddr, at start)."""
    pid = r4("ps -eo pid,args | awk '/[d]hcrelay -4/{print $1; exit}'").strip()
    if not pid.isdigit():
        raise SystemExit("REFUSED: dhcrelay is not running")
    argv = r4(f"tr '\\0' ' ' < /proc/{pid}/cmdline").strip()
    if not argv.startswith("/usr/local/sbin/dhcrelay "):
        raise SystemExit("REFUSED: dhcrelay argv not recognised")
    r4(f"kill {pid}; sleep 1")
    run(["docker", "exec", "-d", R4["container"], "sh", "-c", f"exec {argv} >/dev/null 2>&1"])


def verify_relay(target: str) -> dict:
    spec = RELAY[target]
    if target == "R4":
        addrs = json.loads(r4(f"ip -j -4 addr show dev {spec['interface']}", check=False) or "[]")
        local = [f"{a['local']}/{a['prefixlen']}" for a in (addrs[0].get("addr_info") if addrs else [])]
        relay = r4("ps -eo args | grep '[d]hcrelay'", check=False).strip()
        return {"device": "R4", "addresses": local, "gateway_present": spec["gateway"] in local,
                "giaddr_would_be": local[0] if local else "", "dhcrelay_running": bool(relay),
                "dhcrelay_server": relay.split()[-1] if relay else ""}
    brief = _json(target, f"show ip interface {spec['interface']}").get("interfaces", {}).get(spec["interface"], {})
    secondaries = [f"{a.get('address')}/{a.get('maskLen')}" for a in (brief.get("interfaceAddress") or {}).get("secondaryIpsOrderedList") or []]
    section = eos(target, f"show running-config interfaces {spec['interface']}")
    return {"device": target, "secondary": secondaries, "gateway_present": spec["gateway"] in secondaries,
            "all_subnets": "ip dhcp relay all-subnets" in section, "helper": f"ip helper-address {spec['helper']}" in section}


# --- verify (facts only) -----------------------------------------------------------------------------------------------------
def _json(device: str, command: str) -> dict:
    try:
        return json.loads(eos(device, f"{command} | json"))
    except (json.JSONDecodeError, SystemExit):
        return {}


def verify_eos(device: str) -> dict:
    spec = EOS[device]
    brief = _json(device, f"show ip interface vrf {VRF} brief").get("interfaces") or {}
    members = sorted(brief)
    wanted = {f"{parent}.{VID}": str(ipaddress.ip_interface(cidr).ip) for parent, cidr, _d in spec["subs"]}
    addresses = {name: str(((data.get("interfaceAddress") or {}).get("ipAddr") or {}).get("address") or "") for name, data in brief.items()}
    routes = (_json(device, f"show ip route vrf {VRF}").get("vrfs") or {}).get(VRF, {}).get("routes") or {}
    ret = routes.get(f"{NMAS_SOURCE}/32") or {}
    hops = [via.get("nexthopAddr") for via in ret.get("vias") or []]
    default_vrf = (_json(device, "show ip route").get("vrfs") or {}).get("default", {}).get("routes") or {}
    leaked = sorted(p for p in default_vrf if p.startswith("10.254.251."))
    ssh = eos(device, "show management ssh")
    ssh_vrf = bool(re.search(rf"(?im)^\s*VRF\s*:?\s*{VRF}\b|vrf {VRF}", ssh)) or VRF in ssh
    up = {name: (data.get("lineProtocolStatus"), data.get("interfaceStatus")) for name, data in brief.items()}
    return {"device": device, "vrf_members": members, "members_are_subinterfaces": all("." in m for m in members),
            "addresses_ok": all(addresses.get(k) == v for k, v in wanted.items()),
            "subinterfaces_up": all(up.get(k, ("", ""))[0] == "up" for k in wanted),
            "return_route_nexthops": hops, "return_route_ok": hops == [spec["return_hop"]],
            "default_vrf_has_mgmt_prefix": bool(leaked), "ssh_in_vrf_reported": ssh_vrf}


def verify_r4() -> dict:
    sub = f"{R4['parent']}.{VID}"
    link = json.loads(r4(f"ip -j -d link show {sub} 2>/dev/null || echo []", check=False) or "[]")
    master = (link[0].get("master") if link else "") or ""
    table = r4(f"ip route show table {TABLE}", check=False)
    rules = r4("ip rule show", check=False)
    main = r4("ip route show table main", check=False)
    return {"device": "R4", "subinterface": bool(link), "master": master, "table_routes": len(table.splitlines()),
            "return_route": f"{NMAS_SOURCE} dev {R4['svi']}" in table, "r7_route": "10.254.251.4/30 via 10.254.251.2" in table,
            "policy_rule": f"from {NMAS_SOURCE} to {PREFIX} iif {R4['svi']} lookup {TABLE}" in rules,
            "main_table_has_mgmt_prefix": "10.254.251." in main}


def verify_host() -> dict:
    route = run(["ip", "route", "get", "10.254.251.6", "from", NMAS_SOURCE, "oif", NMAS_IF], check=False)
    return {"host_route": f"via {GATEWAY_V200} dev {NMAS_IF}" in route}


def reach(endpoint: str) -> dict:
    """TCP/22 from a socket bound to nmas-mgmt + the NMAS source (the probe's own L3 shape; no credential is offered)."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, NMAS_IF.encode())
    except OSError:
        pass                                     # unprivileged: the source bind below still selects the attachment's route
    try:
        sock.bind((NMAS_SOURCE, 0))
        sock.connect((endpoint, 22))
        banner = sock.recv(64).decode(errors="replace").split("\r")[0][:40]
        return {"endpoint": endpoint, "tcp22": True, "banner_is_ssh": banner.startswith("SSH-")}
    except OSError as exc:
        return {"endpoint": endpoint, "tcp22": False, "error": type(exc).__name__}
    finally:
        sock.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("action", choices=["plan", "apply", "confirm", "verify", "rollback", "relay-apply", "relay-verify",
                                           "relay-rollback", "relay-window", "relay-window-restore"])
    parser.add_argument("target", choices=["host", "R4", "R6", "R7", "all"])
    parser.add_argument("--session", default=SESSION, help="the EOS configure session to confirm")
    args = parser.parse_args(argv)
    targets = ["host", "R4", "R6", "R7"] if args.target == "all" else [args.target]
    if args.action in ("apply", "confirm") and args.target == "all":
        raise SystemExit("apply / confirm one target at a time (R4, then R6, verify, then R7)")
    out = []
    if args.action.startswith("relay"):
        relay_targets = [t for t in targets if t in RELAY]
        for target in relay_targets:
            if args.action == "relay-apply":
                out.append(apply_relay(target))
            elif args.action == "relay-verify":
                out.append(verify_relay(target))
            elif args.action == "relay-rollback":
                out.append(rollback_relay(target))
            elif target == "R4":
                out.append(relay_window_r4(restore=args.action == "relay-window-restore"))
        print(json.dumps(out, indent=1))
        return 0
    for target in targets:
        if args.action == "plan":
            out.append({"target": target, "lines": eos_lines(target) if target in EOS else
                        ([RULE, *[f"table {TABLE} {p} {n}" for p, n in R4_ROUTES]] if target == "R4" else [f"{PREFIX} via {GATEWAY_V200}"])})
        elif args.action == "apply":
            out.append(apply_eos(target) if target in EOS else (apply_r4() or verify_r4()) if target == "R4" else (apply_host() or verify_host()))
        elif args.action == "confirm":
            out.append(confirm_eos(target, args.session) if target in EOS else {"target": target, "note": "Linux changes need no confirm"})
        elif args.action == "verify":
            out.append(verify_eos(target) if target in EOS else verify_r4() if target == "R4" else verify_host())
            if target in EOS:
                out.append(reach(EOS[target]["endpoint"]))
        else:
            out.append(rollback_eos(target) if target in EOS else (rollback_r4() or verify_r4()) if target == "R4" else (rollback_host() or verify_host()))
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
