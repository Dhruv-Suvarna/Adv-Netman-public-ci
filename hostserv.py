#!/usr/bin/env python3

import time

WEB4 = "172.30.50.10"
WEB6 = "2001:db8:3050::10"


def console_exec(lab, node, docker, command):
    """Credential-free fixed container target; command text is repository-owned."""
    name = f"clab-{lab}-{node}"
    return docker(["exec", name, "bash", "-lc", command]).stdout


def bootstrap_linux_ssh(lab, node, docker, log):
    name = f"clab-{lab}-{node}"

    script = r"""
set -e

export DEBIAN_FRONTEND=noninteractive

if ! command -v sshd >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq \
        openssh-server \
        iproute2 \
        iputils-ping \
        curl \
        isc-dhcp-client
fi

mkdir -p /run/sshd

sed -ri 's/^#?PermitRootLogin .*/PermitRootLogin no/' \
    /etc/ssh/sshd_config

sed -ri 's/^#?PasswordAuthentication .*/PasswordAuthentication no/' \
    /etc/ssh/sshd_config

grep -q '^PermitRootLogin ' /etc/ssh/sshd_config || \
    printf '%s\n' 'PermitRootLogin no' >> /etc/ssh/sshd_config
grep -q '^PasswordAuthentication ' /etc/ssh/sshd_config || \
    printf '%s\n' 'PasswordAuthentication no' >> /etc/ssh/sshd_config

ssh-keygen -A

/usr/sbin/sshd -t

if pgrep -x sshd >/dev/null 2>&1; then
    kill -HUP "$(pgrep -o -x sshd)"
else
    /usr/sbin/sshd
fi

passwd -l root >/dev/null

printf 'host_private_keys=%s\n' \
    "$(find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' | wc -l)"
"""

    p = docker(["exec", name, "bash", "-lc", script])
    log(
        f"SSH BOOTSTRAP {node}",
        p.stdout + p.stderr,
    )

    print(f"{node}: SSH OK")


def configure_webserver(lab, node, docker, log=None):
    cmd = r"""
set -e

export DEBIAN_FRONTEND=noninteractive

if ! command -v apache2 >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq apache2
fi

# ============================================================
# WEBSERVER NETWORK CONFIGURATION
#
# eth1:
#   IPv4 transit  = 172.31.50.1/31
#   IPv6 transit  = 2001:db8:3150::2/64
#
# lo:
#   IPv4 service  = 172.30.50.10/32
#   IPv6 service  = 2001:db8:3050::10/128
#
# IMPORTANT:
# Do not use:
#
#   ip addr flush dev eth1
#
# because that can remove the IPv6 link-local address and break
# NDP toward R5.
# ============================================================

ip link set eth1 up
ip link set dev eth1 mtu 1500

# Remove only the addresses that we intend to rebuild.
# Preserve an existing IPv6 link-local address.
ip -4 addr flush dev eth1 2>/dev/null || true
ip -6 addr flush dev eth1 scope global 2>/dev/null || true

# Ensure the interface has a usable IPv6 link-local address.
# Normally Linux creates one automatically. If an earlier
# configuration run removed it, install a deterministic fallback.
if ! ip -6 -o addr show dev eth1 scope link | grep -q 'inet6 fe80:'; then
    ip -6 addr add fe80::2/64 dev eth1
fi

# Transit addressing toward R5.
ip addr add 172.31.50.1/31 dev eth1
ip -6 addr add 2001:db8:3150::2/64 dev eth1

# Service addresses.
ip addr replace 172.30.50.10/32 dev lo
ip -6 addr replace 2001:db8:3050::10/128 dev lo
ip link set lo up

# Default routes toward R5.
ip route replace default via 172.31.50.0 dev eth1
ip -6 route replace default via 2001:db8:3150::1 dev eth1

# Verify that the required IPv6 link-local address exists.
if ! ip -6 -o addr show dev eth1 scope link | grep -q 'inet6 fe80:'; then
    echo "ERROR: WebServer eth1 has no IPv6 link-local address"
    exit 1
fi

# ============================================================
# APACHE CONFIGURATION
# ============================================================

printf '%s\n' 'Hello world' > /var/www/html/index.html

grep -q '^ServerName ' /etc/apache2/apache2.conf || \
    echo 'ServerName localhost' >> /etc/apache2/apache2.conf

apache2ctl configtest

if pgrep -x apache2 >/dev/null 2>&1; then
    apache2ctl graceful
else
    apache2ctl start
fi

sleep 1

# ============================================================
# LOCAL HTTP VERIFICATION
# ============================================================

curl -fsS http://127.0.0.1/ \
    | grep -q 'Hello world'

curl -fsS http://172.30.50.10/ \
    | grep -q 'Hello world'

curl -g -fsS 'http://[2001:db8:3050::10]/' \
    | grep -q 'Hello world'
"""

    out = console_exec(lab, node, docker, cmd)

    if log:
        log(
            "WebServer configuration",
            out,
        )

    print("WebServer: configuration and local HTTP OK")


def _wait_for_address(lab, node, docker, family, timeout=20):
    if family == 4:
        test = "ip -4 -o addr show dev eth1 scope global"
    else:
        test = "ip -6 -o addr show dev eth1 scope global"

    end = time.time() + timeout

    while time.time() < end:
        out = console_exec(lab, node, docker, test).strip()

        if out:
            return out

        time.sleep(1)

    return ""


def configure_host(lab, node, docker, ipv4=True, ipv6=True, log=None):
    console_exec(
        lab, node, docker,
        "pkill dhclient 2>/dev/null || true; "
        "ip -4 addr flush dev eth1 || true; "
        "ip -6 addr flush dev eth1 scope global || true; "
        "ip route del default 2>/dev/null || true; "
        "ip -6 route del default 2>/dev/null || true; "
        "ip link set eth1 down; "
        "ip link set eth1 up; "
        "ip link set dev eth1 mtu 1500; "
        "sleep 2",
    )

    if ipv4:
        console_exec(
            lab, node, docker,
            "dhclient -4 -v eth1 "
            ">/tmp/dhclient4.log 2>&1 &",
        )

    if ipv6:
        console_exec(
            lab, node, docker,
            "dhclient -6 -v eth1 "
            ">/tmp/dhclient6.log 2>&1 &",
        )

    time.sleep(8)

    out = console_exec(
        lab, node, docker,
        "echo '--- addr ---'; "
        "ip -br addr show eth1; "
        "echo '--- dhcp4 ---'; "
        "cat /tmp/dhclient4.log 2>/dev/null || true; "
        "echo '--- dhcp6 ---'; "
        "cat /tmp/dhclient6.log 2>/dev/null || true",
    )

    has_v4 = not ipv4 or "192.168." in out
    has_v6 = not ipv6 or "2001:db8:" in out

    if log:
        log(
            f"HOST DHCP {node}",
            out,
        )

    missing = []

    if ipv4 and not has_v4:
        missing.append("IPv4 DHCP")

    if ipv6 and not has_v6:
        missing.append("DHCPv6")

    if missing:
        print(
            f"{node}: address acquisition FAILED "
            f"({', '.join(missing)}) - see Run_Logs.log"
        )
        return False

    print(f"{node}: address acquisition OK")

    return True


def verify_linux(lab, node, docker, log):
    details = console_exec(
        lab, node, docker,
        "ip -br addr show eth1; "
        "echo '--- routes ---'; "
        "ip route; "
        "ip -6 route",
    )

    tests = [
        (
            "curl6",
            f"curl -6 -g -fsS "
            f"--connect-timeout 3 "
            f"--max-time 8 "
            f"'http://[{WEB6}]/'",
        )
    ]

    if node != "H4":
        tests.insert(
            0,
            (
                "curl4",
                f"curl -4 -fsS "
                f"--connect-timeout 3 "
                f"--max-time 8 "
                f"http://{WEB4}/",
            ),
        )

    results = []

    for label, cmd in tests:
        try:
            out = console_exec(lab, node, docker, cmd).strip()

            ok = out == "Hello world"

            results.append(
                (
                    label,
                    ok,
                    out if out else "empty response",
                )
            )

        except Exception as e:
            results.append(
                (
                    label,
                    False,
                    str(e),
                )
            )

    verification_output = (
        details
        + "\n"
        + "\n".join(
            f"{name}: {'OK' if ok else 'FAIL'} - {msg}"
            for name, ok, msg in results
        )
    )

    log(
        f"LINUX VERIFY {node}",
        verification_output,
    )

    if all(ok for _, ok, _ in results):
        print(f"{node}: verification OK")
        return True

    print(f"{node}: verification FAILED - see Run_Logs.log")
    return False
