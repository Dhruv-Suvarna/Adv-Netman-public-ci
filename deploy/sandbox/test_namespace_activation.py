#!/usr/bin/env python3
"""Disposable root integration tests for VM-local veth namespace activation.

Run explicitly with ``python3 deploy/sandbox/test_namespace_activation.py``.

Every object lives in a temporary ``nmas-test-*`` network namespace, including
the stand-in for VM1 itself, so the real host never gains a link, address,
route, rule or nft object. All addresses are synthetic and only exist inside
those namespaces; nothing here can reach a real network.

    nmas-test-lab  (simulated Containerlab management LAN)
        198.51.100.1  fd00:51::1   approved device
        198.51.100.2  fd00:51::2   adjacent, unauthorized device
        2606:4700::1               where a leaked IPv6 default route would land
    nmas-test-host (simulated VM1: forwarding on, IPv6 default only via the lab)
        nmas-test-mg0 198.51.100.100 fd00:51::100   like nmas-mgmt
        nmas-test-ex0 10.224.76.50/22               like ens33
    nmas-test-wan  (simulated campus gateway and internet)
        10.224.76.10   simulated vCenter        10.224.77.20  simulated student VM
        93.184.216.34  approved public HTTPS    93.184.216.53 approved resolver
        93.184.217.9   public but operator-protected (EXTRA_DENY_CIDRS)
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTROLLER = HERE / "namespace_activation.py"
DIAG_NS, RESEARCH_NS = "nmas-test-diag", "nmas-test-research"
HOST_NS, LAB_NS, WAN_NS = "nmas-test-host", "nmas-test-lab", "nmas-test-wan"
MGMT, EXTERNAL = "nmas-test-mg0", "nmas-test-ex0"
HOST_LINKS = {"diagnostic": "nmas-test-dh0", "research": "nmas-test-rh0"}
HOST_TABLES = {"diagnostic": "nmas_host_diagnostic", "research": "nmas_host_research"}
DIAGNOSTIC_STEPS = ("netns", "marker", "loopback", "ipv4_forwarding", "ipv6_forwarding", "accept_ra", "nft", "host_nft",
                    "link", "host_marker", "host_move", "ipv4_address", "ipv4_host_address", "ipv6_address",
                    "ipv6_host_address", "host_up", "interface", "ipv4_route", "ipv6_route")
RESEARCH_STEPS = ("netns", "marker", "loopback", "ipv4_forwarding", "ipv6_forwarding", "accept_ra", "ipv6_disable", "nft",
                  "host_nft", "link", "host_marker", "host_move", "ipv4_address", "ipv4_host_address", "host_up",
                  "interface", "ipv4_route", "dns")
ENDPOINT = """
import selectors, socket, sys
sels = selectors.DefaultSelector()
ports = tuple(int(value) for value in sys.argv[1].split(','))
for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
    for port in ports:
        sock = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port)); sock.listen(); sock.setblocking(False); sels.register(sock, selectors.EVENT_READ)
while True:
    for key, _ in sels.select():
        connection, peer = key.fileobj.accept(); connection.sendall(peer[0].encode()); connection.close()
"""
TLS_ENDPOINT = """
import socket, ssl, sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(('93.184.216.34', 443)); listener.listen()
while True:
    raw, _peer = listener.accept()
    try:
        with context.wrap_socket(raw, server_side=True) as tls:
            tls.recv(8192)
            body = b'vendor documentation'
            tls.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: 20\\r\\nConnection: close\\r\\n\\r\\n' + body)
    except (OSError, ssl.SSLError):
        raw.close()
"""


def run(argv: list[str], *, ok: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=capture)
    if ok and result.returncode:
        raise AssertionError(f"command failed ({result.returncode}): {argv}\n{result.stdout}\n{result.stderr}")
    if ok is False and result.returncode == 0:
        raise AssertionError(f"command unexpectedly passed: {argv}")
    return result


def sudo(*argv: str, ok: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return run(["sudo", "-n", *argv], ok=ok, capture=capture)


def ip(namespace: str, *argv: str, **kwargs: bool) -> subprocess.CompletedProcess[str]:
    return sudo("/usr/sbin/ip", "-n", namespace, *argv, **kwargs)


def inside(namespace: str, *argv: str, **kwargs: bool) -> subprocess.CompletedProcess[str]:
    return sudo("/usr/sbin/ip", "netns", "exec", namespace, *argv, **kwargs)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def privileged_digest(path: Path) -> str:
    return sudo("/usr/bin/sha256sum", str(path), capture=True).stdout.split()[0]


def privileged_text(path: Path) -> str:
    return sudo("/bin/cat", str(path), capture=True).stdout


def privileged_write_json(path: Path, value: dict) -> None:
    payload = json.dumps(value, indent=1, sort_keys=True) + "\n"
    sudo("/usr/bin/python3", "-c",
         "import os,sys; p=sys.argv[1]; fd=os.open(p,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW); "
         "os.write(fd,sys.argv[2].encode()); os.fsync(fd); os.close(fd)", str(path), payload)


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def controller(root: Path, action: str, kind: str, config: Path, *, fail_after: str | None = None,
               ok: bool = True) -> subprocess.CompletedProcess[str]:
    argv = controller_argv(root, action, kind, config)
    if fail_after:
        argv += ["--fail-after", fail_after]
    return sudo(*argv, ok=ok, capture=True)


def controller_argv(root: Path, action: str, kind: str, config: Path) -> list[str]:
    return ["/usr/bin/python3", "-I", str(CONTROLLER), action, kind, str(config), "--test-root", str(root)]


def research_service_preflight(root: Path, config: Path, *, bind: bool = True,
                               ok: bool = True) -> subprocess.CompletedProcess[str]:
    """Emulate systemd's private read-only resolver bind inside the research netns."""
    resolver = root / "etc-netns" / RESEARCH_NS / "resolv.conf"
    script = (
        'set -eu; '
        'if [ "$1" = bind ]; then '
        '  /usr/bin/mount --bind "$2" /etc/resolv.conf; '
        '  /usr/bin/mount -o remount,bind,ro /etc/resolv.conf; '
        '  if /usr/bin/truncate -s 0 /etc/resolv.conf 2>/dev/null; then exit 90; fi; '
        'fi; '
        'exec /usr/bin/python3 -I "$3" service-preflight research "$4" --test-root "$5"'
    )
    return inside(RESEARCH_NS, "/usr/bin/unshare", "--mount", "--propagation", "private",
                  "/bin/sh", "-c", script, "nmas-service-preflight", "bind" if bind else "skip",
                  str(resolver), str(CONTROLLER), str(config), str(root), ok=ok, capture=True)


def research_broker_probe(root: Path, certificate: Path) -> subprocess.CompletedProcess[str]:
    resolver = root / "etc-netns" / RESEARCH_NS / "resolv.conf"
    code = (
        "import ssl; "
        "from core.services.troubleshooting.research import ResearchBroker, _PinnedHTTPS; "
        "ctx=ssl.create_default_context(cafile=__import__('sys').argv[1]); "
        "broker=ResearchBroker(allowed_destinations={'docs.vendor.test':['93.184.216.34']}, "
        "transport=_PinnedHTTPS(timeout=2, context=ctx)); "
        "result=broker.fetch('https://docs.vendor.test/', purpose='verify disposable research path', principal='test'); "
        "assert result.body == 'vendor documentation'; print(result.sha256)"
    )
    script = (
        'set -eu; /usr/bin/mount --bind "$1" /etc/resolv.conf; '
        '/usr/bin/mount -o remount,bind,ro /etc/resolv.conf; '
        'exec /usr/bin/env PYTHONPATH="$2/web" /home/student/Scripts/.venv/bin/python -c "$3" "$4"'
    )
    return inside(RESEARCH_NS, "/usr/bin/unshare", "--mount", "--propagation", "private",
                  "/bin/sh", "-c", script, "nmas-broker-probe", str(resolver), str(ROOT), code,
                  str(certificate), capture=True)


def research_systemd_probe(root: Path, certificate: Path) -> None:
    """Run DNS, TLS and denial probes in the active namespace through real systemd."""
    resolver = root / "etc-netns" / RESEARCH_NS / "resolv.conf"
    protected = root / "diagnostic-credential.fixture"
    protected.write_text("must-not-be-readable\n", encoding="utf-8")
    protected.chmod(0o644)
    unit = f"nmas-research-cycle-{os.getpid()}-{time.time_ns()}.service"
    code = r"""
import socket, ssl, sys
assert open('/etc/resolv.conf').read() == 'nameserver 93.184.216.53\n'
try:
    open(sys.argv[2]).read()
    raise SystemExit('protected credential became readable')
except (PermissionError, FileNotFoundError):
    pass
answers={row[4][0] for row in socket.getaddrinfo('docs.vendor.test',443,socket.AF_INET,socket.SOCK_STREAM)}
assert answers == {'93.184.216.34'}, answers
context=ssl.create_default_context(cafile='/run/nmas-test-ca.pem')
with socket.create_connection(('93.184.216.34',443),2) as raw:
    with context.wrap_socket(raw,server_hostname='docs.vendor.test') as tls:
        tls.sendall(b'GET / HTTP/1.1\r\nHost: docs.vendor.test\r\nConnection: close\r\n\r\n')
        assert b'200 OK' in tls.recv(4096)
for family,address,port in ((socket.AF_INET,'198.51.100.1',443),(socket.AF_INET,'93.184.217.9',443),
                            (socket.AF_INET6,'2606:4700::1',443)):
    probe=socket.socket(family,socket.SOCK_STREAM); probe.settimeout(.4)
    try:
        probe.connect((address,port))
        raise SystemExit('unauthorized connection succeeded')
    except OSError:
        pass
    finally:
        probe.close()
print('systemd-research-dns-tls-denials=PASS')
""".strip()
    result = sudo(
        "/usr/bin/systemd-run", f"--unit={unit}", "--wait", "--collect", "--pipe",
        "--property=Type=oneshot", "--property=DynamicUser=yes", "--property=NoNewPrivileges=yes",
        "--property=PrivateDevices=yes", "--property=PrivateTmp=yes", "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes", "--property=CapabilityBoundingSet=", "--property=RestrictNamespaces=yes",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        f"--property=NetworkNamespacePath=/run/netns/{RESEARCH_NS}",
        f"--property=BindReadOnlyPaths={resolver}:/etc/resolv.conf",
        f"--property=BindReadOnlyPaths={certificate}:/run/nmas-test-ca.pem",
        f"--property=InaccessiblePaths=-{protected}",
        f"--property=InaccessiblePaths=-{root / 'intentionally-absent.fixture'}",
        "/usr/bin/python3", "-c", code, "nmas-systemd-probe", str(protected), capture=True,
    )
    assert "systemd-research-dns-tls-denials=PASS" in result.stdout, (result.stdout, result.stderr)
    protected.unlink()


def refused(root: Path, action: str, kind: str, config: Path, expected: str) -> None:
    result = controller(root, action, kind, config, ok=False)
    assert result.returncode == 65 and expected in result.stderr, (expected, result.stderr)


def ns_exists(name: str) -> bool:
    result = sudo("/usr/sbin/ip", "netns", "list", capture=True)
    return name in {line.split()[0] for line in result.stdout.splitlines() if line.split()}


def host_object_exists(kind: str) -> tuple[bool, bool]:
    link = ip(HOST_NS, "link", "show", "dev", HOST_LINKS[kind], ok=None, capture=True).returncode == 0
    table = inside(HOST_NS, "/usr/sbin/nft", "list", "table", "inet", HOST_TABLES[kind], ok=None,
                   capture=True).returncode == 0
    return link, table


def assert_absent(kind: str, namespace: str) -> None:
    assert not ns_exists(namespace), f"{namespace} survived"
    assert host_object_exists(kind) == (False, False), f"owned {kind} host objects survived"


def snapshot(name: str, state: Path, kind: str) -> tuple[str, ...]:
    return (ip(name, "-j", "address", "show", capture=True).stdout,
            ip(name, "-j", "route", "show", "table", "all", capture=True).stdout,
            inside(name, "/usr/sbin/nft", "-s", "list", "ruleset", capture=True).stdout,
            ip(HOST_NS, "-j", "address", "show", "dev", HOST_LINKS[kind], capture=True).stdout,
            inside(HOST_NS, "/usr/sbin/nft", "-s", "list", "table", "inet", HOST_TABLES[kind], capture=True).stdout,
            privileged_digest(state))


def network_baseline(namespace: str | None) -> dict[str, str]:
    """Addresses, every route table, policy rules and the stateless firewall ruleset."""
    def read(*argv: str) -> str:
        return (inside(namespace, *argv, capture=True) if namespace else sudo(*argv, capture=True)).stdout
    result = {"addresses": read("/usr/sbin/ip", "-j", "address", "show"),
              "links": json.dumps(sorted(link["ifname"] for link in json.loads(read("/usr/sbin/ip", "-j", "link", "show")))),
              "routes4": read("/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"),
              "routes6": read("/usr/sbin/ip", "-j", "-6", "route", "show", "table", "all"),
              "rules4": read("/usr/sbin/ip", "-j", "-4", "rule", "show"),
              "rules6": read("/usr/sbin/ip", "-j", "-6", "rule", "show"),
              "firewall": read("/usr/sbin/nft", "-s", "list", "ruleset"),
              "forwarding": read("/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")}
    if namespace is None:
        # Volatile lifetimes/counters are not configuration; drop them from the real-host comparison.
        for key in ("addresses", "routes4", "routes6"):
            rows = json.loads(result[key])
            for row in rows:
                row.pop("expires", None)
                row.pop("stats64", None)
                for info in row.get("addr_info", []):
                    info.pop("valid_life_time", None)
                    info.pop("preferred_life_time", None)
            result[key] = json.dumps(rows, sort_keys=True)
        result["sshd"] = sudo("/usr/bin/sh", "-c", "cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | sha256sum",
                              capture=True).stdout
        result["netns"] = "\n".join(sorted(line.split()[0] for line in read("/usr/sbin/ip", "netns", "list").splitlines()
                                           if line.split() and not line.startswith("nmas-test-")))
    return result


def assert_baseline(label: str, before: dict[str, str], after: dict[str, str]) -> None:
    changed = [key for key in before if before[key] != after[key]]
    if changed:
        raise AssertionError(f"{label} baseline changed: {changed}")


def assert_pending_cleanup_preserves_foreign_objects(root: Path) -> None:
    """A pending journal entry is never treated as deletion ownership."""
    spec = importlib.util.spec_from_file_location("namespace_activation_race_test", CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    config = {
        "schema": module.SCHEMA,
        "kind": "research",
        "namespace": "nmas-test-race-worker",
        "host_interface": "nmas-test-race0",
        "host_namespace": None,
        "host_table": "nmas_host_race_test",
        "activation_id": "TEST-RACE-ACTIVATION-0001",
        "config_digest": "1" * 64,
        "dns_servers": ["93.184.216.53"],
    }

    def state(pending_step: str) -> dict[str, object]:
        return {
            "schema": module.SCHEMA, "kind": config["kind"], "namespace": config["namespace"],
            "activation_id": config["activation_id"], "config_digest": config["config_digest"],
            "status": "activating", "sequence": 0, "pending_step": pending_step, "completed_steps": [],
            "namespace_owned": False, "marker_owned": False, "host_link_owned": False,
            "host_table_owned": False, "resolver_file_owned": False, "resolver_directory_owned": False,
        }

    # Simulate an unrelated namespace appearing after the controller journals
    # its intent but before ``ip netns add`` fails.  Cleanup must not delete it.
    deleted: list[list[str]] = []
    module.host_link = lambda _config: None
    module.host_table = lambda _config: None
    module.namespace_names = lambda: {config["namespace"]}
    module.ownership_marker = lambda _namespace: "foreign-owner"
    module.command = lambda argv, **_kwargs: deleted.append(argv)
    module.cleanup(config, root / "race-netns-state.json", state("netns"), root / "race-netns-etc", "cleaned")
    assert not deleted, "pending netns step deleted an unowned namespace"

    # Simulate a foreign resolver path winning the mkdir/open race.  Pending
    # intent alone must not authorize unlink/rmdir.
    module.namespace_names = lambda: set()
    resolver_root = root / "race-resolver-etc"
    directory = resolver_root / str(config["namespace"])
    directory.mkdir(parents=True)
    resolver = directory / "resolv.conf"
    foreign = b"foreign-object-never-created-by-controller\n"
    resolver.write_bytes(foreign)
    module.cleanup(config, root / "race-dns-state.json", state("dns"), resolver_root, "cleaned")
    assert resolver.read_bytes() == foreign and directory.is_dir(), "pending DNS step deleted an unowned resolver path"
    shutil.rmtree(resolver_root)


def probe(namespace: str, address: str, port: int, expected: bool, *, seen_as: str | None = None,
          family: int | None = None) -> None:
    """TCP connect from inside ``namespace``; the endpoint answers with the source address it observed."""
    if family is None:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
    code = ("import socket,sys; "
            f"s=socket.socket({int(family)},socket.SOCK_STREAM); s.settimeout(0.5); "
            f"s.connect(({address!r},{port})); sys.stdout.write(s.recv(64).decode()); s.close()")
    result = inside(namespace, "/usr/bin/python3", "-c", code, ok=None, capture=True)
    if expected and result.returncode:
        raise AssertionError(f"{namespace} could not reach approved {address}:{port}\n{result.stderr}")
    if not expected and result.returncode == 0:
        raise AssertionError(f"unexpected connection from {namespace} to {address}:{port}")
    if expected and seen_as is not None and result.stdout != seen_as:
        raise AssertionError(f"{address}:{port} saw source {result.stdout!r}, expected {seen_as!r}")


def probe_udp(namespace: str, address: str, port: int, expected: bool) -> None:
    """Send a minimal DNS query; only the approved resolver should answer."""
    query = "12340100000100000000000004646f63730676656e646f7204746573740000010001"
    code = ("import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(0.6); "
            f"s.sendto(bytes.fromhex('{query}'),('{address}',{port})); data,_=s.recvfrom(512); "
            "sys.stdout.write(str(len(data)))")
    result = inside(namespace, "/usr/bin/python3", "-c", code, ok=None, capture=True)
    if expected and result.returncode:
        raise AssertionError(f"{namespace} could not reach approved UDP {address}:{port}\n{result.stderr}")
    if not expected and result.returncode == 0:
        raise AssertionError(f"unexpected UDP response from {address}:{port}")


def probe_dns_tcp(namespace: str, address: str, expected: bool) -> None:
    query = "12340100000100000000000004646f63730676656e646f7204746573740000010001"
    code = ("import socket,struct,sys; q=bytes.fromhex('" + query + "'); "
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(0.6); "
            f"s.connect(('{address}',53)); s.sendall(struct.pack('!H',len(q))+q); "
            "size=struct.unpack('!H',s.recv(2))[0]; data=s.recv(size); sys.stdout.write(str(len(data)))")
    result = inside(namespace, "/usr/bin/python3", "-c", code, ok=None, capture=True)
    if expected and result.returncode:
        raise AssertionError(f"{namespace} could not use approved TCP DNS {address}:53\n{result.stderr}")
    if not expected and result.returncode == 0:
        raise AssertionError(f"unexpected TCP DNS response from {address}:53")


def config_text(kind: str, namespace: str, policy: Path) -> str:
    research = kind == "research"
    values = {
        "NAMESPACE": kind,
        "ACTIVATION_ID": f"TEST-ACTIVATION-{kind.upper()}-0001",
        "AUTHORIZATION_APPROVED": "yes",
        "AUTHORIZATION_ID": f"TEST-AUTH-{kind.upper()}-0001",
        "EGRESS_INTERFACE": EXTERNAL if research else MGMT,
        "HOST_NETWORKING_APPROVAL_ID": f"TEST-HOSTNET-{kind.upper()}-0001",
        "FIREWALL_POLICY_APPROVAL_ID": f"TEST-NFT-{kind.upper()}-0001",
        "NFT_POLICY": str(policy),
        "NFT_POLICY_SHA256": digest(policy),
        "IPV4_MODE": "enabled",
        "IPV4_LINK_CIDR": "169.254.87.2/30" if research else "169.254.86.2/30",
        "IPV4_GATEWAY": "169.254.87.1" if research else "169.254.86.1",
        "IPV4_NAT": "masquerade" if research else "198.51.100.100",
        "IPV4_NAT_APPROVAL_ID": f"TEST-NAT4-{kind.upper()}-0001",
        "IPV6_MODE": "disabled" if research else "enabled",
        "DNS_MODE": "enabled" if research else "disabled",
        "DNS_SERVERS": "93.184.216.53" if research else "",
        "DNS_TRANSPORTS": "udp,tcp" if research else "",
        "TEST_NAMESPACE_NAME": namespace,
        "TEST_HOST_NAMESPACE": HOST_NS,
    }
    if research:
        values.update({"RESEARCH_EGRESS_APPROVAL_ID": "TEST-RESEARCH-EGRESS-0001", "EXTRA_DENY_CIDRS": "93.184.217.0/24",
                       "HTTPS_TARGETS": "tcp:93.184.216.34:443"})
    else:
        values.update({"IPV6_LINK_CIDR": "fd00:86::2/126", "IPV6_GATEWAY": "fd00:86::1", "IPV6_NAT": "fd00:51::100",
                       "IPV6_NAT_APPROVAL_ID": "TEST-NAT6-DIAGNOSTIC-0001",
                       "TARGETS": "tcp:198.51.100.1:2222 tcp:[fd00:51::1]:2222"})
    return "".join(f"{key}={value}\n" for key, value in values.items())


def make_files(root: Path) -> tuple[Path, Path]:
    (root / "etc-netns").mkdir(mode=0o755)
    diagnostic_nft = root / "diagnostic.nft"
    research_nft = root / "research.nft"
    diagnostic = (HERE / "diagnostic-egress.nft.in").read_text(encoding="utf-8")
    diagnostic = (diagnostic.replace("@TARGETS4@", "elements = { 198.51.100.1 . 2222 }")
                  .replace("@TARGETS6@", "elements = { fd00:51::1 . 2222 }"))
    research = (HERE / "research-egress.nft.in").read_text(encoding="utf-8")
    research = (research.replace("@DNS4@", "elements = { 93.184.216.53 }").replace("@DNS6@", "")
                .replace("@HTTPS4@", "elements = { 93.184.216.34 . 443 }").replace("@HTTPS6@", ""))
    write(diagnostic_nft, diagnostic)
    write(research_nft, research)
    diagnostic_config, research_config = root / "diagnostic.env", root / "research.env"
    write(diagnostic_config, config_text("diagnostic", DIAG_NS, diagnostic_nft))
    write(research_config, config_text("research", RESEARCH_NS, research_nft))
    return diagnostic_config, research_config


def variant(root: Path, source: Path, name: str, *, drop: str = "", **changes: str) -> Path:
    lines = [line for line in source.read_text(encoding="utf-8").splitlines() if line.split("=", 1)[0] != drop]
    lines = [line for line in lines if line.split("=", 1)[0] not in changes]
    lines += [f"{key}={value}" for key, value in changes.items()]
    path = root / name
    write(path, "\n".join(lines) + "\n")
    return path


def setup_network() -> None:
    for namespace in (HOST_NS, LAB_NS, WAN_NS):
        sudo("/usr/sbin/ip", "netns", "add", namespace)
        ip(namespace, "link", "set", "lo", "up")
    # Created inside the simulated host namespace: the real host never sees these links.
    ip(HOST_NS, "link", "add", MGMT, "type", "veth", "peer", "name", "lab0", "netns", LAB_NS)
    ip(HOST_NS, "link", "add", EXTERNAL, "type", "veth", "peer", "name", "wan0", "netns", WAN_NS)
    plan = {
        (HOST_NS, MGMT): ("198.51.100.100/24", "fd00:51::100/64"),
        (HOST_NS, EXTERNAL): ("10.224.76.50/22",),
        (LAB_NS, "lab0"): ("198.51.100.1/24", "198.51.100.2/24", "fd00:51::1/64", "fd00:51::2/64", "2606:4700::1/128"),
        (WAN_NS, "wan0"): ("10.224.76.1/22", "10.224.76.10/22", "10.224.77.20/22", "93.184.216.34/32",
                           "93.184.216.53/32", "93.184.217.9/32"),
    }
    for (namespace, device), addresses in plan.items():
        ip(namespace, "link", "set", device, "addrgenmode", "none")
        ip(namespace, "link", "set", device, "up")
        for address in addresses:
            ip(namespace, "address", "add", address, "dev", device, *(["nodad"] if ":" in address else []))
    # VM1 as discovered: forwarding already on, IPv4 default via the campus side,
    # and an IPv6 default route that leads only into the lab.
    inside(HOST_NS, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
    ip(HOST_NS, "route", "add", "default", "via", "10.224.76.1", "dev", EXTERNAL)
    ip(HOST_NS, "-6", "route", "add", "default", "via", "fd00:51::1", "dev", MGMT)
    # Both neighbours can route straight back to the VM-local links, so a denied
    # probe below is attributable to filtering and never to a missing return path.
    for prefix in ("169.254.86.0/30", "169.254.87.0/30"):
        ip(LAB_NS, "route", "add", prefix, "via", "198.51.100.100")
        ip(WAN_NS, "route", "add", prefix, "via", "10.224.76.50")
    ip(LAB_NS, "-6", "route", "add", "fd00:86::/126", "via", "fd00:51::100")


def start_endpoint(namespace: str) -> subprocess.Popen[str]:
    ports = "22,2222" if namespace == WAN_NS else "22,53,443,2222"
    return subprocess.Popen(["sudo", "-n", "/usr/sbin/ip", "netns", "exec", namespace,
                             "/usr/bin/python3", "-c", ENDPOINT, ports], text=True)


def start_dns_endpoint() -> subprocess.Popen[str]:
    return subprocess.Popen([
        "sudo", "-n", "/usr/sbin/ip", "netns", "exec", WAN_NS,
        "/usr/sbin/dnsmasq", "--no-daemon", "--bind-interfaces", "--listen-address=93.184.216.53",
        "--port=53", "--no-resolv", "--address=/docs.vendor.test/93.184.216.34",
        "--address=/drift.vendor.test/93.184.217.9", "--log-facility=-",
    ], text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_tls_endpoint(certificate: Path, key: Path) -> subprocess.Popen[str]:
    return subprocess.Popen([
        "sudo", "-n", "/usr/sbin/ip", "netns", "exec", WAN_NS,
        "/usr/bin/python3", "-c", TLS_ENDPOINT, str(certificate), str(key),
    ], text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def generate_test_certificate(root: Path) -> tuple[Path, Path]:
    certificate, key = root / "research-test.crt", root / "research-test.key"
    run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=docs.vendor.test", "-addext", "subjectAltName=DNS:docs.vendor.test",
         "-keyout", str(key), "-out", str(certificate)], capture=True)
    return certificate, key


def cleanup(root: Path, endpoints: list[subprocess.Popen[str]]) -> None:
    for endpoint in endpoints:
        subprocess.run(["sudo", "-n", "/usr/bin/pkill", "-P", str(endpoint.pid)], capture_output=True)
        endpoint.terminate()
        try:
            endpoint.wait(timeout=2)
        except subprocess.TimeoutExpired:
            endpoint.kill()
            endpoint.wait()
    for namespace in (DIAG_NS, RESEARCH_NS, HOST_NS, LAB_NS, WAN_NS):
        if ns_exists(namespace):
            for pid in sudo("/usr/sbin/ip", "netns", "pids", namespace, capture=True).stdout.split():
                subprocess.run(["sudo", "-n", "/usr/bin/kill", "-9", pid], capture_output=True)
            sudo("/usr/sbin/ip", "netns", "delete", namespace)
    if root.exists():
        sudo("/bin/chown", "-R", f"{os.getuid()}:{os.getgid()}", str(root))


def main() -> int:
    if shutil.which("sudo") is None or subprocess.run(
            ["sudo", "-n", "/usr/bin/true"], capture_output=True).returncode != 0:
        raise SystemExit("passwordless sudo is required for the disposable namespace test")
    root = Path(tempfile.mkdtemp(prefix="nmas-namespace-test-"))
    endpoints: list[subprocess.Popen[str]] = []
    results: dict[str, object] = {"schema": "nmas.namespace-integration-test/2", "tests": []}
    passed = results["tests"].append  # type: ignore[union-attr]
    real_before = network_baseline(None)
    try:
        assert_pending_cleanup_preserves_foreign_objects(root)
        passed("pending-step-cleanup-preserves-unowned-namespace-and-resolver-objects")
        diagnostic, research = make_files(root)
        certificate, certificate_key = generate_test_certificate(root)
        sudo("/bin/chown", "root:root", str(root / "etc-netns"))
        sudo("/bin/chmod", "0755", str(root / "etc-netns"))
        setup_network()
        endpoints = [start_endpoint(namespace) for namespace in (HOST_NS, LAB_NS, WAN_NS)]
        endpoints += [start_dns_endpoint(), start_tls_endpoint(certificate, certificate_key)]
        time.sleep(0.4)
        host_before = network_baseline(HOST_NS)
        state_d, state_r = root / "state" / "diagnostic.json", root / "state" / "research.json"

        before = sorted(root.rglob("*"))
        controller(root, "preflight", "diagnostic", diagnostic)
        controller(root, "preflight", "research", research)
        assert sorted(root.rglob("*")) == before, "preflight mutated the test root"
        assert_absent("diagnostic", DIAG_NS)
        assert_absent("research", RESEARCH_NS)
        assert_baseline("simulated host after preflight", host_before, network_baseline(HOST_NS))
        passed("mutation-free-preflight")

        sudo("/bin/chmod", "0775", str(root / "etc-netns"))
        refused(root, "preflight", "research", research, "resolver root is missing or unsafe")
        sudo("/bin/chmod", "0755", str(root / "etc-netns"))
        sudo("/bin/chown", f"{os.getuid()}:{os.getgid()}", str(root / "etc-netns"))
        refused(root, "preflight", "research", research, "resolver root is missing or unsafe")
        sudo("/bin/chown", "root:root", str(root / "etc-netns"))
        controller(root, "preflight", "research", research)
        passed("resolver-root-requires-root-owner-and-0755")

        for index, (source, key) in enumerate((
                (diagnostic, "AUTHORIZATION_ID"), (diagnostic, "EGRESS_INTERFACE"), (diagnostic, "IPV4_LINK_CIDR"),
                (diagnostic, "IPV4_NAT_APPROVAL_ID"), (diagnostic, "FIREWALL_POLICY_APPROVAL_ID"),
                (diagnostic, "HOST_NETWORKING_APPROVAL_ID"), (diagnostic, "TARGETS"), (diagnostic, "IPV6_NAT"),
                (research, "DNS_SERVERS"), (research, "RESEARCH_EGRESS_APPROVAL_ID"),
                (research, "HOST_NETWORKING_APPROVAL_ID"), (research, "IPV4_NAT"))):
            kind = "diagnostic" if source == diagnostic else "research"
            controller(root, "preflight", kind, variant(root, source, f"missing-{index}.env", drop=key), ok=False)
        inconsistent = (
            ("diagnostic", {"IPV4_NAT": "masquerade"}, "exact approved existing management source"),
            ("diagnostic", {"IPV4_NAT": "198.51.100.77"}, "not an existing address of the egress interface"),
            ("diagnostic", {"IPV4_LINK_CIDR": "93.184.216.2/30", "IPV4_GATEWAY": "93.184.216.1"}, "must be VM-local"),
            ("diagnostic", {"IPV4_LINK_CIDR": "10.224.76.6/30", "IPV4_GATEWAY": "10.224.76.5"}, "overlaps an address"),
            ("diagnostic", {"IPV4_LINK_CIDR": "169.254.86.2/24"}, "point-to-point"),
            ("diagnostic", {"EGRESS_INTERFACE": "nmas-test-none"}, "egress interface does not exist"),
            ("diagnostic", {"TARGETS": "tcp:198.51.100.0/24:22"}, "TARGETS entry"),
            ("diagnostic", {"TARGETS": "tcp:device.example:22"}, "TARGETS entry"),
            ("diagnostic", {"DNS_MODE": "enabled", "DNS_SERVERS": "93.184.216.53", "DNS_TRANSPORTS": "udp,tcp"},
             "diagnostic DNS must be explicitly disabled"),
            ("diagnostic", {"AUTHORIZATION_APPROVED": "no"}, "AUTHORIZATION_APPROVED"),
            ("research", {"TARGETS": "tcp:198.51.100.1:2222"}, "must not contain diagnostic targets"),
            ("research", {"DNS_SERVERS": "2606:4700:4700::1111"}, "disabled address family"),
            ("research", {"EXTRA_DENY_CIDRS": "not-a-network"}, "EXTRA_DENY_CIDRS"),
            ("research", {"IPV6_LINK_CIDR": "fd00:87::2/126"}, "disabled IPv6 must not contain"),
        )
        for index, (kind, changes, expected) in enumerate(inconsistent):
            source = diagnostic if kind == "diagnostic" else research
            refused(root, "preflight", kind, variant(root, source, f"inconsistent-{index}.env", **changes), expected)
        # Forwarding is never switched on by the controller, and a foreign default-drop
        # forward chain (as Docker installs for IPv6 on VM1) is never bypassed silently.
        inside(HOST_NS, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=0")
        refused(root, "preflight", "research", research, "forwarding is not already enabled")
        inside(HOST_NS, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
        inside(HOST_NS, "/usr/sbin/nft", "add table ip6 nmas_test_foreign; "
               "add chain ip6 nmas_test_foreign FORWARD { type filter hook forward priority filter; policy drop; }")
        refused(root, "preflight", "diagnostic", diagnostic, "foreign default-drop forward chain governs IPv6")
        controller(root, "preflight", "diagnostic", variant(
            root, diagnostic, "foreign-approved.env", IPV6_FOREIGN_FORWARD_APPROVAL_ID="TEST-FOREIGN6-DIAGNOSTIC-0001"))
        controller(root, "preflight", "research", research)
        inside(HOST_NS, "/usr/sbin/nft", "delete", "table", "ip6", "nmas_test_foreign")
        # Pre-existing objects with the owned names are refused and never adopted or deleted.
        inside(HOST_NS, "/usr/sbin/nft", "add", "table", "inet", HOST_TABLES["diagnostic"])
        refused(root, "activate", "diagnostic", diagnostic, "host nft table already exists")
        assert host_object_exists("diagnostic") == (False, True), "unowned table was removed"
        inside(HOST_NS, "/usr/sbin/nft", "delete", "table", "inet", HOST_TABLES["diagnostic"])
        ip(HOST_NS, "link", "add", HOST_LINKS["research"], "type", "dummy")
        refused(root, "activate", "research", research, "host veth name already exists")
        assert host_object_exists("research") == (True, False), "unowned link was removed"
        ip(HOST_NS, "link", "delete", HOST_LINKS["research"])
        assert_absent("diagnostic", DIAG_NS)
        assert_absent("research", RESEARCH_NS)
        assert_baseline("simulated host after refusals", host_before, network_baseline(HOST_NS))
        passed("missing-unapproved-inconsistent-configuration-refused-without-mutation")

        controller(root, "prepare-resolver", "research", research)
        controller(root, "prepare-resolver", "research", research)
        assert (root / "etc-netns" / RESEARCH_NS / "resolv.conf").read_text() == "nameserver 93.184.216.53\n"
        controller(root, "preflight", "research", research)
        passed("resolver-prepared-and-verified-before-network-activation")

        controller(root, "activate", "diagnostic", diagnostic)
        controller(root, "activate", "diagnostic", diagnostic)
        controller(root, "validate", "diagnostic", diagnostic)
        assert not ns_exists(RESEARCH_NS), "diagnostic activation created the research namespace"
        controller(root, "prepare-resolver", "research", research)
        controller(root, "activate", "research", research)
        controller(root, "activate", "research", research)
        controller(root, "validate", "research", research)
        passed("independent-idempotent-activation-validation")

        # The service consumes the lifecycle-owned resolver through the same
        # file bind declared by BindReadOnlyPaths=. All mutations below are in
        # the disposable fixture; the host resolver is compared byte-for-byte.
        resolver = root / "etc-netns" / RESEARCH_NS / "resolv.conf"
        research_policy = root / "research.nft"
        policy_bytes = research_policy.read_bytes()
        sudo("/bin/chown", "root:root", str(research), str(research_policy))
        sudo("/bin/chmod", "0600", str(research), str(research_policy))
        global_resolver_before = privileged_digest(Path("/etc/resolv.conf"))
        result = research_service_preflight(root, research)
        assert '"result": "valid"' in result.stdout
        broker_result = research_broker_probe(root, certificate)
        assert broker_result.stdout.strip(), broker_result.stderr
        assert privileged_digest(Path("/etc/resolv.conf")) == global_resolver_before
        result = research_service_preflight(root, research, bind=False, ok=False)
        assert result.returncode == 65 and "not the exact approved resolver file" in result.stderr

        missing_backup = resolver.with_name("resolv.conf.missing-test")
        sudo("/bin/mv", str(resolver), str(missing_backup))
        result = research_service_preflight(root, research, ok=False)
        assert result.returncode != 0
        sudo("/bin/mv", str(missing_backup), str(resolver))

        sudo("/bin/chown", f"{os.getuid()}:{os.getgid()}", str(resolver))
        result = research_service_preflight(root, research, ok=False)
        assert result.returncode == 65 and "root-owned non-symlink" in result.stderr
        sudo("/bin/chown", "root:root", str(resolver))

        original_resolver = resolver.read_bytes()
        sudo("/usr/bin/python3", "-c", "from pathlib import Path; Path(__import__('sys').argv[1]).write_bytes(b'nameserver 203.0.113.53\\n')", str(resolver))
        result = research_service_preflight(root, research, ok=False)
        assert result.returncode == 65 and "differs from approved DNS_SERVERS" in result.stderr
        sudo("/usr/bin/python3", "-c", "from pathlib import Path; Path(__import__('sys').argv[1]).write_bytes(__import__('sys').argv[2].encode())",
             str(resolver), original_resolver.decode())

        resolver_backup = resolver.with_name("resolv.conf.owned")
        sudo("/bin/mv", str(resolver), str(resolver_backup))
        sudo("/bin/ln", "-s", str(resolver_backup), str(resolver))
        result = research_service_preflight(root, research, ok=False)
        assert result.returncode == 65 and "root-owned non-symlink" in result.stderr
        sudo("/bin/unlink", str(resolver))
        sudo("/bin/mv", str(resolver_backup), str(resolver))

        sudo("/usr/bin/python3", "-c", "from pathlib import Path; p=Path(__import__('sys').argv[1]); p.write_bytes(p.read_bytes()+b'\\n# drift\\n')",
             str(research_policy))
        result = research_service_preflight(root, research, ok=False)
        assert result.returncode == 65 and "NFT_POLICY_SHA256" in result.stderr
        sudo("/usr/bin/python3", "-c", "from pathlib import Path; Path(__import__('sys').argv[1]).write_bytes(__import__('sys').argv[2].encode())",
             str(research_policy), policy_bytes.decode())
        controller(root, "validate", "research", research)
        assert privileged_digest(Path("/etc/resolv.conf")) == global_resolver_before
        sudo("/bin/chown", f"{os.getuid()}:{os.getgid()}", str(research), str(research_policy))
        passed("service-namespace-readonly-resolver-bind-and-drift-fail-closed")

        # 1. approved device, reached from the existing management source address (no new lab address).
        probe(DIAG_NS, "198.51.100.1", 2222, True, seen_as="198.51.100.100")
        probe(DIAG_NS, "fd00:51::1", 2222, True, seen_as="fd00:51::100")
        passed("diagnostic-reaches-approved-device-ipv4-ipv6-from-existing-management-source")
        # 2. adjacent endpoint and unapproved port on the approved device.
        for address, port in (("198.51.100.2", 2222), ("fd00:51::2", 2222), ("198.51.100.1", 22), ("198.51.100.1", 443),
                              ("fd00:51::1", 443)):
            probe(DIAG_NS, address, port, False)
        passed("diagnostic-denied-adjacent-endpoint-and-unapproved-port")
        # 3. simulated vCenter, student VM, internet, and VM1's own services.
        for address, port in (("10.224.76.10", 443), ("10.224.76.10", 22), ("10.224.77.20", 22), ("10.224.76.1", 443),
                              ("93.184.216.34", 443), ("2606:4700::1", 443), ("198.51.100.100", 22),
                              ("169.254.86.1", 22), ("10.224.76.50", 22), ("fd00:86::1", 22)):
            probe(DIAG_NS, address, port, False)
        passed("diagnostic-denied-vcenter-student-vm-internet-and-host-services")
        # 4. approved public HTTPS, seen behind VM1's existing external address.
        research_broker_probe(root, certificate)
        probe_dns_tcp(RESEARCH_NS, "93.184.216.53", True)
        probe_udp(RESEARCH_NS, "93.184.216.53", 53, True)
        passed("research-reaches-public-https-and-approved-resolver-behind-existing-host-address")
        # 5. private, campus, Containerlab and host destinations; non-HTTPS; operator-protected public range.
        for address, port in (("10.224.76.10", 443), ("10.224.77.20", 443), ("10.224.76.1", 443), ("198.51.100.1", 2222),
                              ("198.51.100.1", 443), ("198.51.100.100", 443), ("169.254.87.1", 443),
                              ("169.254.86.2", 2222), ("10.224.76.50", 443), ("93.184.216.34", 22),
                              ("93.184.216.34", 53), ("93.184.217.9", 443)):
            probe(RESEARCH_NS, address, port, False)
        for address, port in (("93.184.216.34", 53), ("93.184.216.34", 443), ("93.184.217.9", 53),
                              ("10.224.76.10", 53), ("198.51.100.1", 53)):
            probe_udp(RESEARCH_NS, address, port, False)
        passed("research-denied-private-campus-containerlab-host-and-protected-destinations")
        # 6/7. IPv4-mapped IPv6 and native IPv6 (VM1's only IPv6 default route leads into the lab).
        for address in ("::ffff:10.224.76.10", "::ffff:198.51.100.1", "::ffff:169.254.87.1", "2606:4700::1",
                        "fd00:51::1", "::1"):
            probe(RESEARCH_NS, address, 443, False, family=socket.AF_INET6)
        probe(DIAG_NS, "::ffff:10.224.76.10", 443, False, family=socket.AF_INET6)
        probe(DIAG_NS, "::ffff:198.51.100.2", 2222, False, family=socket.AF_INET6)
        passed("ipv4-mapped-ipv6-and-native-ipv6-containment")

        diagnostic_before = snapshot(DIAG_NS, state_d, "diagnostic")
        controller(root, "rollback", "research", research)
        assert diagnostic_before == snapshot(DIAG_NS, state_d, "diagnostic")
        controller(root, "validate", "diagnostic", diagnostic)
        assert_absent("research", RESEARCH_NS)
        probe(DIAG_NS, "198.51.100.1", 2222, True, seen_as="198.51.100.100")
        passed("research-rollback-preserves-diagnostic")

        controller(root, "prepare-resolver", "research", research)
        controller(root, "activate", "research", research)
        research_before = snapshot(RESEARCH_NS, state_r, "research")
        controller(root, "rollback", "diagnostic", diagnostic)
        assert research_before == snapshot(RESEARCH_NS, state_r, "research")
        controller(root, "validate", "research", research)
        assert_absent("diagnostic", DIAG_NS)
        research_broker_probe(root, certificate)
        passed("diagnostic-rollback-preserves-research")

        for step in DIAGNOSTIC_STEPS:
            controller(root, "activate", "diagnostic", diagnostic, fail_after=step, ok=False)
            assert_absent("diagnostic", DIAG_NS)
            assert research_before[:5] == snapshot(RESEARCH_NS, state_r, "research")[:5], step
            controller(root, "validate", "research", research)
        passed("diagnostic-every-step-failure-cleans-only-owned-resources")

        controller(root, "activate", "diagnostic", diagnostic)
        diagnostic_before = snapshot(DIAG_NS, state_d, "diagnostic")
        controller(root, "rollback", "research", research)
        for step in RESEARCH_STEPS:
            if step == "dns":
                controller(root, "prepare-resolver", "research", research, fail_after=step, ok=False)
            else:
                controller(root, "prepare-resolver", "research", research)
                controller(root, "activate", "research", research, fail_after=step, ok=False)
            assert_absent("research", RESEARCH_NS)
            assert not (root / "etc-netns" / RESEARCH_NS).exists(), step
            assert diagnostic_before[:5] == snapshot(DIAG_NS, state_d, "diagnostic")[:5], step
            controller(root, "validate", "diagnostic", diagnostic)
        passed("research-every-step-failure-cleans-only-owned-resources")

        # A namespace that lost its own policy and gained a default route (a fully
        # compromised worker) is still contained by the host table; validation
        # reports the drift instead of repairing it, and rollback still succeeds.
        controller(root, "prepare-resolver", "research", research)
        controller(root, "activate", "research", research)
        inside(DIAG_NS, "/usr/sbin/nft", "flush", "ruleset")
        ip(DIAG_NS, "route", "add", "default", "via", "169.254.86.1")
        ip(DIAG_NS, "-6", "route", "add", "default", "via", "fd00:86::1")
        probe(DIAG_NS, "198.51.100.1", 2222, True, seen_as="198.51.100.100")
        for address, port in (("198.51.100.2", 2222), ("fd00:51::2", 2222), ("198.51.100.1", 22), ("10.224.76.10", 443),
                              ("10.224.77.20", 22), ("93.184.216.34", 443), ("2606:4700::1", 443),
                              ("198.51.100.100", 22), ("169.254.86.1", 22), ("169.254.87.2", 443)):
            probe(DIAG_NS, address, port, False)
        refused(root, "validate", "diagnostic", diagnostic, "differ")
        inside(RESEARCH_NS, "/usr/sbin/nft", "flush", "ruleset")
        research_broker_probe(root, certificate)
        for address, port in (("10.224.76.10", 443), ("10.224.77.20", 443), ("198.51.100.1", 2222), ("198.51.100.1", 443),
                              ("198.51.100.100", 443), ("10.224.76.50", 443), ("169.254.87.1", 443),
                              ("169.254.86.2", 2222), ("93.184.216.34", 22), ("93.184.217.9", 443)):
            probe(RESEARCH_NS, address, port, False)
        probe(RESEARCH_NS, "::ffff:198.51.100.1", 443, False, family=socket.AF_INET6)
        refused(root, "validate", "research", research, "nft table set differs")
        controller(root, "validate", "diagnostic", diagnostic, ok=False)
        passed("host-side-containment-holds-for-compromised-namespace-and-drift-is-reported")

        # A changed ownership marker blocks deletion; restoring it lets rollback proceed.
        marker = json.loads(ip(HOST_NS, "-j", "link", "show", "dev", HOST_LINKS["research"], capture=True).stdout)[0]["ifalias"]
        ip(HOST_NS, "link", "set", "dev", HOST_LINKS["research"], "alias", "someone-else")
        refused(root, "rollback", "research", research, "host veth ownership marker changed")
        assert ns_exists(RESEARCH_NS) and host_object_exists("research") == (True, True)
        ip(HOST_NS, "link", "set", "dev", HOST_LINKS["research"], "alias", marker)
        other = variant(root, research, "other-activation.env", ACTIVATION_ID="TEST-ACTIVATION-RESEARCH-0002")
        refused(root, "rollback", "research", other, "state ownership mismatch")
        assert ns_exists(RESEARCH_NS) and host_object_exists("research") == (True, True)
        passed("changed-marker-and-cross-activation-rollback-refused")

        controller(root, "deactivate", "diagnostic", diagnostic)
        diagnostic_receipt = privileged_digest(state_d)
        controller(root, "deactivate", "diagnostic", diagnostic)
        assert diagnostic_receipt == privileged_digest(state_d)
        controller(root, "rollback", "research", research)
        research_receipt = privileged_digest(state_r)
        controller(root, "rollback", "research", research)
        assert research_receipt == privileged_digest(state_r)
        assert_absent("diagnostic", DIAG_NS)
        assert_absent("research", RESEARCH_NS)
        research_generations = []
        rolled_back_receipts = []
        for _cycle in range(3):
            for kind, config, namespace in (("diagnostic", diagnostic, DIAG_NS), ("research", research, RESEARCH_NS)):
                if kind == "research":
                    controller(root, "prepare-resolver", kind, config)
                controller(root, "activate", kind, config)
                controller(root, "validate", kind, config)
            probe(DIAG_NS, "198.51.100.1", 2222, True, seen_as="198.51.100.100")
            research_broker_probe(root, certificate)
            research_systemd_probe(root, certificate)
            controller(root, "rollback", "research", research)
            controller(root, "rollback", "diagnostic", diagnostic)
            assert_absent("diagnostic", DIAG_NS)
            assert_absent("research", RESEARCH_NS)
            receipt = privileged_text(state_r)
            state_value = json.loads(receipt)
            assert state_value["status"] == "rollback" and not any(
                state_value.get(flag) for flag in (
                    "namespace_owned", "marker_owned", "host_link_owned", "host_table_owned",
                    "resolver_file_owned", "resolver_directory_owned"))
            assert state_value["generation"] not in research_generations
            research_generations.append(state_value["generation"])
            rolled_back_receipts.append(receipt)
        history = root / "state" / "history" / "research"
        history_names = sudo("/usr/bin/find", str(history), "-maxdepth", "1", "-type", "f", "-name", "*.json",
                             "-print", capture=True).stdout.splitlines()
        archived = {privileged_text(Path(name)) for name in history_names}
        assert set(rolled_back_receipts[:-1]).issubset(archived)
        assert len(set(research_generations)) == 3
        passed("research-three-distinct-generations-real-systemd-and-preserved-history")

        # Reproduce the exact live retry blocker: the preserved receipt was
        # written by schema v2, is status=rollback and has every ownership flag
        # false. It must be archived byte-for-byte, never rewritten in place,
        # before a clean v3 generation starts.
        legacy = json.loads(rolled_back_receipts[-1])
        legacy["schema"] = "nmas.namespace-activation/2"
        spec = importlib.util.spec_from_file_location("namespace_activation_legacy_digest_test", CONTROLLER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(module)
        normalized = module.normalized_config(research, "research", test_mode=True)
        legacy["config_digest"] = normalized["legacy_config_digests"][legacy["schema"]]
        assert legacy["config_digest"] != normalized["config_digest"]
        for key in tuple(legacy):
            if key == "generation" or key == "generation_started_at" or key.startswith("previous_"):
                legacy.pop(key)
        privileged_write_json(state_r, legacy)
        legacy_receipt = privileged_text(state_r)
        controller(root, "prepare-resolver", "research", research)
        migrated = json.loads(privileged_text(state_r))
        assert migrated["schema"] == "nmas.namespace-activation/3"
        assert migrated["previous_generation"].startswith("legacy-")
        assert migrated["previous_receipt_sha256"] == hashlib.sha256(legacy_receipt.encode()).hexdigest()
        assert privileged_text(Path(migrated["previous_receipt_path"])) == legacy_receipt
        controller(root, "activate", "research", research)
        research_systemd_probe(root, certificate)
        controller(root, "rollback", "research", research)
        passed("legacy-v2-rollback-receipt-starts-v3-generation-and-remains-byte-preserved")

        # A terminal receipt is reusable only when both its journal and the
        # filesystem prove that the prior generation is completely absent.
        terminal_receipt = json.loads(privileged_text(state_r))
        stale = dict(terminal_receipt)
        stale["resolver_file_owned"] = True
        privileged_write_json(state_r, stale)
        refused(root, "prepare-resolver", "research", research, "stale or ambiguous ownership")
        privileged_write_json(state_r, terminal_receipt)

        partial = dict(terminal_receipt)
        partial["status"] = "activation-failed-cleanup-required"
        privileged_write_json(state_r, partial)
        refused(root, "prepare-resolver", "research", research, "not in a reusable terminal state")
        privileged_write_json(state_r, terminal_receipt)

        foreign_directory = root / "etc-netns" / RESEARCH_NS
        sudo("/bin/mkdir", str(foreign_directory))
        refused(root, "prepare-resolver", "research", research, "conflicts with existing or foreign resources")
        sudo("/bin/rmdir", str(foreign_directory))
        passed("stale-partial-and-foreign-terminal-state-refused")

        # Preparation followed by host drift remains recoverable without
        # adopting the foreign object or discarding the prepared generation.
        controller(root, "prepare-resolver", "research", research)
        prepared_generation = json.loads(privileged_text(state_r))["generation"]
        ip(HOST_NS, "link", "add", HOST_LINKS["research"], "type", "dummy")
        refused(root, "activate", "research", research, "host veth name already exists")
        assert json.loads(privileged_text(state_r))["generation"] == prepared_generation
        ip(HOST_NS, "link", "delete", HOST_LINKS["research"])
        controller(root, "activate", "research", research)
        controller(root, "rollback", "research", research)
        passed("host-filesystem-change-between-preparation-and-activation-fails-closed")

        # Replacing an owned resolver with the same bytes but another inode
        # does not transfer cleanup authority to the replacement.
        controller(root, "prepare-resolver", "research", research)
        resolver = root / "etc-netns" / RESEARCH_NS / "resolv.conf"
        owned_resolver = resolver.with_name("resolv.conf.owned-inode")
        sudo("/bin/mv", str(resolver), str(owned_resolver))
        sudo("/bin/cp", "--preserve=mode,ownership", str(owned_resolver), str(resolver))
        refused(root, "rollback", "research", research, "resolver file inode changed")
        sudo("/bin/unlink", str(resolver))
        sudo("/bin/mv", str(owned_resolver), str(resolver))
        controller(root, "rollback", "research", research)

        controller(root, "prepare-resolver", "research", research)
        owned_resolver = resolver.with_name("resolv.conf.owned-symlink")
        sudo("/bin/mv", str(resolver), str(owned_resolver))
        sudo("/bin/ln", "-s", str(owned_resolver), str(resolver))
        refused(root, "rollback", "research", research, "owned research resolver file must be")
        sudo("/bin/unlink", str(resolver))
        sudo("/bin/mv", str(owned_resolver), str(resolver))
        controller(root, "rollback", "research", research)
        passed("resolver-inode-and-symlink-replacement-never-inherits-cleanup-authority")

        # A foreign entry forces a partial rollback. The receipt keeps its
        # ownership flags until an operator removes only the foreign blocker;
        # retrying prepare cannot silently advance the generation.
        controller(root, "prepare-resolver", "research", research)
        foreign_entry = root / "etc-netns" / RESEARCH_NS / "foreign.audit"
        sudo("/usr/bin/touch", str(foreign_entry))
        refused(root, "rollback", "research", research, "not empty")
        refused(root, "prepare-resolver", "research", research, "owned research resolver file is missing")
        sudo("/bin/unlink", str(foreign_entry))
        controller(root, "rollback", "research", research)
        passed("partial-rollback-blocks-new-generation-and-recovers-idempotently")

        # Temporary files left before atomic rename are ignored. The current
        # receipt remains authoritative, and later atomic writes never adopt
        # the interrupted file.
        interrupted = root / "state" / ".research.json.interrupted"
        sudo("/usr/bin/install", "-o", "root", "-g", "root", "-m", "0600", "/dev/null", str(interrupted))
        controller(root, "prepare-resolver", "research", research)
        sudo("/usr/bin/test", "-f", str(interrupted))
        controller(root, "rollback", "research", research)
        sudo("/bin/unlink", str(interrupted))
        passed("interrupted-atomic-receipt-write-does-not-authorize-or-block-a-generation")

        # The per-kind flock serializes concurrent attempts. The second
        # process cannot create a generation until the first lock holder exits.
        ready = root / "research-lock-ready"
        holder = subprocess.Popen([
            "sudo", "-n", "/usr/bin/python3", "-c",
            "import fcntl,os,sys,time; fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600); "
            "fcntl.flock(fd,fcntl.LOCK_EX); open(sys.argv[2],'w').close(); time.sleep(1.5)",
            str(root / "state" / "research.lock"), str(ready),
        ], text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists() and holder.poll() is None
        waiter = subprocess.Popen(
            ["sudo", "-n", *controller_argv(root, "prepare-resolver", "research", research)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(0.25)
        assert waiter.poll() is None, "concurrent activation bypassed the lifecycle lock"
        assert not (root / "etc-netns" / RESEARCH_NS).exists()
        assert holder.wait(timeout=3) == 0, holder.stderr.read() if holder.stderr else ""
        stdout, stderr = waiter.communicate(timeout=5)
        assert waiter.returncode == 0, (stdout, stderr)
        controller(root, "rollback", "research", research)
        ready.unlink()
        passed("concurrent-activation-attempts-are-serialized")

        # A receipt from an older generation cannot clean up resources marked
        # by the current one, even if an operator accidentally places it at the
        # current receipt path. Restoring the current receipt permits recovery.
        controller(root, "prepare-resolver", "research", research)
        controller(root, "activate", "research", research)
        active_receipt = json.loads(privileged_text(state_r))
        old_receipt = json.loads(rolled_back_receipts[0])
        privileged_write_json(state_r, old_receipt)
        refused(root, "rollback", "research", research, "namespace inode changed")
        assert ns_exists(RESEARCH_NS) and host_object_exists("research") == (True, True)
        privileged_write_json(state_r, active_receipt)
        controller(root, "rollback", "research", research)

        controller(root, "prepare-resolver", "research", research)
        controller(root, "activate", "research", research)
        active_receipt = json.loads(privileged_text(state_r))
        mismatched = dict(active_receipt)
        mismatched["generation"] = "f" * 32 if active_receipt["generation"] != "f" * 32 else "e" * 32
        privileged_write_json(state_r, mismatched)
        refused(root, "rollback", "research", research, "ownership marker changed")
        privileged_write_json(state_r, active_receipt)
        controller(root, "rollback", "research", research)
        passed("old-or-mismatched-generation-cannot-authorize-current-resource-cleanup")

        # Receipt paths themselves are no-follow. An attacker-controlled link
        # is rejected before any namespace or resolver mutation.
        receipt_backup = state_r.with_name("research.json.owned")
        sudo("/bin/mv", str(state_r), str(receipt_backup))
        sudo("/bin/ln", "-s", str(receipt_backup), str(state_r))
        refused(root, "prepare-resolver", "research", research, "trusted-owner mode-0600 regular file")
        sudo("/bin/unlink", str(state_r))
        sudo("/bin/mv", str(receipt_backup), str(state_r))
        controller(root, "rollback", "research", research)
        passed("receipt-symlink-replacement-is-refused-without-mutation")

        passed("idempotent-deactivate-rollback-and-repeated-cycles")

        assert_baseline("simulated host", host_before, network_baseline(HOST_NS))
        passed("simulated-host-address-route-rule-firewall-forwarding-baseline-restored")
        results["result"] = "PASS"
    finally:
        cleanup(root, endpoints)
        shutil.rmtree(root, ignore_errors=True)
    assert_baseline("real host", real_before, network_baseline(None))
    passed("real-host-address-route-rule-firewall-ssh-namespace-baseline-untouched")
    print(json.dumps(results, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
