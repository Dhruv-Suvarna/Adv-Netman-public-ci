"""Continuous production probes for a transition: sequence-numbered echo flows between the client hosts and the service.

Each flow is one ``ping -D -O -i <interval>`` inside a host container.  A probe is lost when its sequence number was
sent, is older than ``hold`` seconds and has no reply line: a missing sequence number counts as loss.  ICMP sequence
numbers are 16 bits wide, so a flow is restarted (``maintain``) well before they wrap; the new generation starts before
the old one stops, so no moment is unobserved.

Only these fixed commands are ever run, always as ``docker exec <host container> ...``: ``ping``, ``awk``, ``kill``.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import time
import uuid
from dataclasses import dataclass

DIRECTORY = "/tmp/nmas-transition-probes"
# Between two stages of a run every flow must have delivered at least this share of the samples its interval calls for.
# Measured on the loaded sandbox (host load 27): 79 % of nominal at 100 per second, 90 % at 50 per second.
ADVANCE_FRACTION, ADVANCE_MINIMUM_SECONDS = 0.5, 10.0
_LABEL = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_COUNT = r"""/bytes from/ && match($0,/seq=[0-9]+/){s=substr($0,RSTART+4,RLENGTH-4)+0; if(!n||s<lo)lo=s; if(s>hi)hi=s; seen[s]=1; n++}
END{h=int(%s); for(s=lo;s<=hi-h;s++) if(!(s in seen)) lost++; print lost+0, n+0, hi-lo+1}"""


@dataclass(frozen=True)
class Flow:
    label: str
    container: str
    destination: str
    interval: float = 0.02
    source: str = ""                 # the address to probe from, when it is not the one the host would pick (a service loopback)

    def __post_init__(self):
        ipaddress.ip_address(self.destination)
        if self.source and ipaddress.ip_address(self.source).version != ipaddress.ip_address(self.destination).version:
            raise ValueError(f"{self.label}: source and destination are different address families")
        if not _LABEL.fullmatch(self.label) or not 0.005 <= float(self.interval) <= 1.0 or not self.container:
            raise ValueError(f"invalid probe flow {self.label!r}")

    @property
    def target(self) -> str:
        """The validated tail of the ping command: family, optional source, destination."""
        family = "-6" if ipaddress.ip_address(self.destination).version == 6 else "-4"
        source = f" -I {ipaddress.ip_address(self.source)}" if self.source else ""
        return f"{family}{source} {ipaddress.ip_address(self.destination)}"


def _docker(container: str, argv: list[str], *, detach: bool = False, timeout: float = 30.0):
    return subprocess.run(["docker", "exec", *(["-d"] if detach else []), "-u", "0", container, *argv],  # noqa: S603 - fixed argv, shell=False
                          capture_output=True, text=True, timeout=timeout, shell=False, check=False)


class HostProbes:
    """``start()`` ... ``healthy()`` / ``lost()`` / ``maintain()`` ... ``stop()``; ``report()`` is the per-flow evidence."""

    def __init__(self, flows, *, runner=None, window_seconds: float = 240.0, hold_seconds: float = 3.0, clock=time.monotonic, sleep=time.sleep):
        self.flows = list(flows)
        if len({flow.label for flow in self.flows}) != len(self.flows) or not self.flows:
            raise ValueError("probe flows need unique labels")
        self._run, self._window, self._hold, self._clock, self._sleep = runner or _docker, window_seconds, hold_seconds, clock, sleep
        self._generation, self._started_at = 0, None
        self._run_id = uuid.uuid4().hex[:12]            # this instance's own files: a dead earlier run's probes can never write into them
        self._closed = {flow.label: [0, 0] for flow in self.flows}       # label -> [lost, answered] of finished generations
        self._progress = None                                            # (clock, {label: samples}) of the last judged reading
        self.errors: list[str] = []

    # -- one generation ---------------------------------------------------------------------------------------------------
    def _paths(self, flow: Flow, generation: int) -> tuple[str, str]:
        stem = f"{DIRECTORY}/{flow.label}.{self._run_id}.{generation}"
        return f"{stem}.log", f"{stem}.pid"

    def _launch(self, generation: int) -> None:
        for flow in self.flows:
            if generation == 1:          # resolve the first hop before counting: the first packet of a cold flow is not evidence of anything
                self._run(flow.container, ["sh", "-c", f"ping -c 2 -i 0.2 -W 1 {flow.target} > /dev/null 2>&1"])
            log, pid = self._paths(flow, generation)
            # -w: a probe whose owner died (a killed worker) ends on its own and never runs forever.  900 s is longer than any
            # generation can live: at the fastest interval (10 ms) the 16-bit sequence wraps after 655 s, which ``maintain`` precedes
            deadline = max(900, int(3 * self._window))
            script = f"mkdir -p {DIRECTORY}; echo $$ > {pid}; exec ping -D -O -w {deadline} -i {float(flow.interval)} {flow.target} > {log} 2>&1"
            done = self._run(flow.container, ["sh", "-c", script], detach=True)
            if done.returncode:
                self.errors.append(f"{flow.label}: probe did not start")

    def _count(self, flow: Flow, generation: int, *, final: bool) -> tuple[int, int]:
        log, _pid = self._paths(flow, generation)
        hold = 0 if final else self._hold / float(flow.interval)
        done = self._run(flow.container, ["awk", _COUNT % hold, log])
        try:
            lost, answered, _span = (int(part) for part in done.stdout.split())
        except ValueError:
            self.errors.append(f"{flow.label}: probe log unreadable")
            return 0, 0
        return lost, answered

    def _halt(self, generation: int) -> None:
        for flow in self.flows:
            _log, pid = self._paths(flow, generation)
            self._run(flow.container, ["sh", "-c", f"kill -INT $(cat {pid})"])
        for flow in self.flows:
            lost, answered = self._count(flow, generation, final=True)
            self._closed[flow.label][0] += lost
            self._closed[flow.label][1] += answered

    @property
    def run_id(self) -> str:
        return self._run_id

    def halt_run(self, run_id: str) -> None:
        """Stop every probe a DEAD earlier instance with ``run_id`` left running in these flows' containers (its owner was
        killed and never stopped them).  Only that run's own pid files are read; nothing else is signalled."""
        if not re.fullmatch(r"[0-9a-f]{12}", str(run_id)):
            raise ValueError("not a probe run id")
        for container in sorted({flow.container for flow in self.flows}):
            # only a process that still is a ping: a pid the kernel has reused since is never signalled
            self._run(container, ["sh", "-c", f"for f in {DIRECTORY}/*.{run_id}.*.pid; do [ -f \"$f\" ] || continue; p=$(cat \"$f\"); "
                                             f"[ \"$(cat /proc/$p/comm 2>/dev/null)\" = ping ] && kill -INT $p; done; true"])

    # -- lifecycle --------------------------------------------------------------------------------------------------------
    def start(self) -> None:
        self._generation += 1
        self._launch(self._generation)
        self._started_at = self._clock()

    def maintain(self) -> None:
        """Restart every flow before its sequence numbers wrap.  The new generation overlaps the old one by more than
        ``hold`` seconds, so every instant is covered by a counted probe."""
        if self._started_at is None or self._clock() - self._started_at < self._window:
            return
        previous = self._generation
        self.start()
        self._sleep(self._hold + 1.0)
        # the old generation's tail is covered by the new one: its last ``hold`` seconds are not judged twice
        for flow in self.flows:
            _log, pid = self._paths(flow, previous)
            self._run(flow.container, ["sh", "-c", f"kill -INT $(cat {pid})"])
        for flow in self.flows:
            log, _pid = self._paths(flow, previous)
            done = self._run(flow.container, ["awk", _COUNT % (self._hold / float(flow.interval)), log])
            try:
                lost, answered, _span = (int(part) for part in done.stdout.split())
            except ValueError:
                self.errors.append(f"{flow.label}: probe log unreadable")
                continue
            self._closed[flow.label][0] += lost
            self._closed[flow.label][1] += answered

    def stop(self) -> None:
        if self._started_at is not None:
            self._sleep(self._hold)
            self._halt(self._generation)
            self._started_at = None

    # -- evidence ---------------------------------------------------------------------------------------------------------
    def report(self) -> list[dict]:
        rows = []
        for flow in self.flows:
            lost, answered = self._closed[flow.label]
            if self._started_at is not None:
                now_lost, now_answered = self._count(flow, self._generation, final=False)
                lost, answered = lost + now_lost, answered + now_answered
            rows.append({"flow": flow.label, "destination": flow.destination, "answered": answered, "lost": lost})
        return rows

    def lost(self) -> int:
        """Cumulative lost probes of every flow.  An unreadable or unstarted flow is a loss: evidence is never assumed."""
        return sum(row["lost"] for row in self.report()) + len(self.errors)

    def advancing(self, *, minimum_seconds: float = ADVANCE_MINIMUM_SECONDS, fraction: float = ADVANCE_FRACTION) -> tuple[bool, dict]:
        """Whether every flow kept producing samples since the previous judged call.  A flow that delivered fewer than
        ``fraction`` of the samples its interval calls for is unreliable timing: "0 lost" of samples that were never
        taken is not evidence.  The first call, and a call less than ``minimum_seconds`` after the reference, only
        set or keep the reference."""
        now = self._clock()
        counts = {row["flow"]: row["answered"] + row["lost"] for row in self.report()}
        if self.errors:
            return False, {"judged": True, "stalled_flows": [], "errors": self.errors[:5]}
        if self._progress is None:
            self._progress = (now, counts)
            return True, {"judged": False}
        then, before = self._progress
        elapsed = now - then
        if elapsed < minimum_seconds:
            return True, {"judged": False}
        self._progress = (now, counts)
        slow = {flow.label: [counts[flow.label] - before.get(flow.label, 0), int(elapsed / float(flow.interval))] for flow in self.flows
                if counts[flow.label] - before.get(flow.label, 0) < fraction * elapsed / float(flow.interval)}
        return not slow, {"judged": True, "elapsed_seconds": round(elapsed, 1), "stalled_flows": sorted(slow),
                          "samples_seen_of_expected": {label: slow[label] for label in sorted(slow)[:5]}, "errors": []}

    def healthy(self, *, minimum: int = 100) -> tuple[bool, dict]:
        rows = self.report()
        quiet = [row["flow"] for row in rows if row["answered"] < minimum]
        lost = sum(row["lost"] for row in rows)
        return not quiet and not lost and not self.errors, {"lost": lost, "answered": sum(row["answered"] for row in rows),
                                                            "flows": len(rows), "unanswered_flows": quiet, "errors": self.errors[:5]}
