"""Fixtures for the traffic workbench tests: a scripted CONTAINER RUNTIME under the real traffic runner.

``wired()`` replaces only two things: the Unix socket (the website's request document is handed, JSON-encoded, straight to a real
``Engine``) and the runtime module (``World`` instead of ``docker``).  Everything between them is the real code: the website's validation
and request document, the runner's own revalidation, the engine, the reply check and the verdict.  Nothing is spawned.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from unittest import mock

from core.services.traffic import client, endpoints
from core.services.traffic.runner import config as runner_config
from core.services.traffic.runner import engine as runner_engine
from core.services.traffic.runner import runtime

IMAGE = "sha256:" + "ab" * 32
PEER_UID = 4242
IDS = {f"clab-srlceos01-{name}": f"{index:064x}" for index, name in enumerate(("H1", "H2", "H3", "H4", "WebServer"), start=1)}
NODES = {identity: container.rsplit("-", 1)[1] for container, identity in IDS.items()}
ADDRESSES = {"H1": ("192.168.10.102", "2001:db8:10::2001"), "H2": ("192.168.20.101", "2001:db8:20::2001"),
             "H3": ("192.168.10.103", "2001:db8:10::2003"), "H4": (None, "2001:db8:30::18e5"), "WebServer": ("172.31.50.1", "2001:db8:3150::e979")}

PING_OK = """PING 192.168.20.101 (192.168.20.101) 56(84) bytes of data.
64 bytes from 192.168.20.101: icmp_seq=1 ttl=62 time=2.45 ms

--- 192.168.20.101 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 2.454/5.143/10.257/3.617 ms
"""
PING_LOSS = "--- x ping statistics ---\n3 packets transmitted, 1 received, 66.6667% packet loss, time 2010ms\nrtt min/avg/max/mdev = 1.0/1.0/1.0/0.0 ms\n"
PING_DEAD = "--- x ping statistics ---\n3 packets transmitted, 0 received, 100% packet loss, time 2040ms\n"
TRACE_OK = "traceroute to 192.168.20.101 (192.168.20.101), 15 hops max, 60 byte packets\n 1  * \n 2  192.168.20.101  10.002 ms\n"
TRACE_V6 = "traceroute to 2001:db8:20::2001 (2001:db8:20::2001), 15 hops max, 80 byte packets\n 1  2001:db8:10::1  1.2 ms\n 2  2001:db8:20::2001  3.4 ms\n"
TRACE_SHORT = "traceroute to 192.168.20.101 (192.168.20.101), 2 hops max\n 1  192.168.10.1  1.1 ms\n 2  * \n"


def iperf_tcp(bps=1047038.25):
    return json.dumps({"start": {}, "end": {"sum_sent": {"bits_per_second": bps + 1400, "bytes": 393216, "seconds": 3.0, "retransmits": 2},
                                           "sum_received": {"bits_per_second": bps, "bytes": 393216, "seconds": 3.004}}})


def iperf_udp(lost=3, packets=300):
    return json.dumps({"end": {"sum": {"bits_per_second": 999000.0, "bytes": 375000, "seconds": 3.0, "jitter_ms": 0.412,
                                       "lost_packets": lost, "packets": packets, "lost_percent": 100.0 * lost / packets}}})


def runner_configuration(**overrides):
    document = endpoints.runner_config(tools_image=IMAGE, allowed_peer_uids=[PEER_UID])
    document.update(overrides)
    return runner_config.parse(document)


class World:
    """A scripted container runtime with the interface of ``runner.runtime``.  ``outputs[tool]`` is the stdout (or a Completed) of the
    next run of that tool.  ``containers`` is what exists right now -- a test asserts it is empty afterwards."""

    def __init__(self):
        self.calls: list[tuple] = []           # (endpoint node, tool, [args]) of every tool run; a server start is "server:<tool>"
        self.argv: list[list] = []             # the REAL docker argv the runtime module would have used, for every container started
        self.outputs: dict = {"ping": PING_OK, "traceroute": TRACE_OK, "iperf3": iperf_tcp(), "tcp_connect": '{"result": "connected", "elapsed_ms": 1.5}',
                              "udp_probe": '{"result": "open_or_filtered", "sent": 3, "replies": 0, "elapsed_ms": 6000.1}'}
        self.timeouts: set = set()
        self.server_listens, self.server_exits, self.port_busy = True, True, False
        self.image_present, self.start_fails, self.unremovable = True, set(), set()
        self.missing: set = set()               # endpoint containers that do not exist
        self.vanish_during: set = set()         # tools after whose run the SOURCE endpoint is gone
        self.containers: dict = {}              # name -> {"running", "exit_code", "logs"}
        self.removed: list = []
        self.inspected: list = []

    # --- the runtime interface ---------------------------------------------------------------------------------------------------
    def inspect_endpoint(self, container, *, lab, node):
        self.inspected.append(container)
        if lab != "srlceos01":
            raise runtime.RuntimeFailure("ENDPOINT_WRONG_LAB")
        if container in self.missing or container not in IDS:
            raise runtime.RuntimeFailure("ENDPOINT_NOT_FOUND")
        return IDS[container]

    def image_available(self, image):
        return self.image_present and image == IMAGE

    def run_tool(self, *, name, instance, run_id, netns, image, tool, args, timeout):
        self.argv.append(runtime._run_args(name=name, instance=instance, run_id=run_id, netns=netns, image=image, tool=tool, args=args,
                                           detached=False))        # the REAL allowlist / argument validation always applies
        node, args = NODES[netns], [str(a) for a in args]
        self.calls.append((node, tool, args))
        if tool in self.start_fails:
            return runtime.Completed(125, "", "docker: Error response from daemon")
        if tool in self.vanish_during:
            self.missing.add(f"clab-srlceos01-{node}")
            return runtime.Completed(137, "", "")
        if tool == "ip":
            v4, v6 = ADDRESSES[node]
            info = [{"local": a, "scope": "global"} for a in (v4, v6) if a] + [{"local": "fe80::1", "scope": "link"}]
            return runtime.Completed(0, json.dumps([{"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "scope": "host"}]},
                                                    {"ifname": "eth0", "addr_info": [{"local": "172.20.20.9", "scope": "global"}]},
                                                    {"ifname": "eth1", "operstate": "UP", "addr_info": info}]), "")
        if tool in self.timeouts:
            self.containers[name] = {"running": True, "exit_code": 0, "logs": ""}      # the client was killed; its container still runs
            return runtime.Completed(-1, "", "", timed_out=True)
        output = self.outputs[tool]
        if tool == "iperf3" and self.server_exits:
            for other in self.containers.values():       # a one-off server exits after serving its client
                other["running"] = False
        return output if isinstance(output, runtime.Completed) else runtime.Completed(0, output, "")

    def start_server(self, *, name, instance, run_id, netns, image, tool, args):
        self.argv.append(runtime._run_args(name=name, instance=instance, run_id=run_id, netns=netns, image=image, tool=tool, args=args,
                                           detached=True))
        self.calls.append((NODES[netns], "server:" + tool, [str(a) for a in args]))
        if "server" in self.start_fails:
            return runtime.Completed(125, "", "docker: Error response from daemon")
        up = self.server_listens and not self.port_busy
        self.containers[name] = {"running": up, "exit_code": 0 if up else 1, "logs": "Server listening on 5201 (test #1)\n" if up else "iperf3: error - unable to start listener"}
        return runtime.Completed(0, "f" * 64 + "\n", "")

    def container_state(self, name):
        runtime._own(name)
        found = self.containers.get(name)
        return None if found is None else {"running": found["running"], "exit_code": found["exit_code"]}

    def logs(self, name):
        return self.containers[runtime._own(name)]["logs"]

    def remove(self, name):
        self.removed.append(runtime._own(name))
        if not any(name.endswith(suffix) for suffix in self.unremovable):
            self.containers.pop(name, None)

    def owned(self, instance):
        return sorted(self.containers)

    # --- assertions --------------------------------------------------------------------------------------------------------------
    def tools(self):
        return [tool for _node, tool, _args in self.calls if tool != "ip"]


class Wired:
    def __init__(self, world, engine):
        self.world, self.engine, self.requests, self.replies = world, engine, [], []

    def __getattr__(self, name):                 # a test reads the world through the wiring: ``w.calls``, ``w.containers`` ...
        return getattr(self.world, name)

    def submit(self, run):
        request = json.loads(json.dumps(client.document(run)))
        self.requests.append(request)
        reply = json.loads(json.dumps(self.engine.handle(request, peer_uid=PEER_UID)))
        self.replies.append(reply)
        return client.check(reply, run)


@contextmanager
def wired(world=None, **config):
    world = world or World()
    engine = runner_engine.Engine(runner_configuration(**config), runtime=world, sleep=lambda seconds: None)
    wiring = Wired(world, engine)
    with mock.patch.object(client, "submit", wiring.submit):
        yield wiring


def request(**overrides) -> dict:
    data = {"source": "H1", "destination": "H2", "address_family": "IPV4", "family": "ICMP"}
    data.update(overrides)
    return data
