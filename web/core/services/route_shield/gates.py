"""Fail-closed prechecks of a shielded transition.  Pure: evidence in, blocker codes out.  No I/O, no device access.

Every code below stops the transition before the first configuration line is sent.
"""

from __future__ import annotations

import ipaddress
import os
import re

from . import model

OLD_ROUTE_ABSENT = "EXPECTED_OLD_ROUTE_ABSENT"
NEW_PATH_UNAVAILABLE = "NEW_PATH_UNAVAILABLE"
NEXT_HOP_UNHEALTHY = "ALTERNATE_NEXT_HOP_UNHEALTHY"
CLASSIFICATION_UNKNOWN = "ROUTE_CLASSIFICATION_UNKNOWN"
PROBES_UNHEALTHY = "PRODUCTION_PROBES_UNHEALTHY"
SHIELD_UNCONFIRMED = "SHIELD_NOT_CONFIRMED"
MANAGEMENT_FALLBACK = "MANAGEMENT_ROUTE_WOULD_FORWARD"
BASELINE_STALE = "CONFIG_BASELINE_STALE"
OUT_OF_BAND = "OUT_OF_BAND_CHANGE"
HOST_GATE = "HOST_RESOURCE_GATE_FAILED"
EVIDENCE_UNAVAILABLE = "LIVE_EVIDENCE_UNAVAILABLE"
PACKET_LOSS = "PRODUCTION_PACKET_LOSS"
WINDOW_CONDITION_LOST = "WINDOW_CONDITION_LOST"            # between two stages: the host left the window's resource condition
PROBE_TIMING_UNRELIABLE = "PROBE_TIMING_UNRELIABLE"        # between two stages: a probe flow stopped delivering samples
UPSTREAM_COVER_UNCONFIRMED = "UPSTREAM_COVER_NOT_CONFIRMED"

KNOWN_TYPES = ("static", "isis", "connected", "ospf", "bgp", "rip", "attached", "receive", "kernel")


def _is_management(name: str) -> bool:
    return str(name).lower().startswith(("management", "ma"))


def _kind(route: dict) -> str:
    text = str(route.get("type", "")).lower()
    return next((known for known in KNOWN_TYPES if text.startswith(known)), "")


def _routes(routes, prefix: str) -> list[dict]:
    wanted = str(ipaddress.ip_network(prefix))
    return [route for route in routes if route.get("prefix") == wanted]


def _owned_by(routes, prefix: str, owner: model.Owner) -> bool:
    for route in _routes(routes, prefix):
        if _kind(route) == owner.source and owner.interface in route.get("interfaces", ()) and \
                (owner.source != model.STATIC or not owner.next_hop or owner.next_hop in route.get("next_hops", ())):
            return True
    return False


def precheck(transition: model.Transition, evidence, *, next_hop_alive=None, new_route_available=None) -> list[dict]:
    """Blockers for ``transition`` from ONE fresh read of its device.  ``evidence`` is a health ``DeviceEvidence``.

    ``next_hop_alive(device, address) -> bool`` and ``new_route_available(transition) -> bool`` are the two facts the read
    groups cannot give (a neighbour that answers; a route a protocol holds but has not installed).  A missing callable is
    a failed check, never a pass.
    """
    found: list[dict] = []

    def block(code: str, detail: str) -> None:
        found.append({"code": code, "device": transition.device, "detail": detail})

    routes, interfaces, isis = (evidence.facts(name) if evidence is not None else None for name in ("routes", "interfaces", "isis"))
    if routes is None or interfaces is None or isis is None:
        block(EVIDENCE_UNAVAILABLE, "routes, interfaces and IS-IS adjacencies must all be readable")
        return found
    for prefix in transition.protected:
        present = _routes(routes, prefix)
        if any(not _kind(route) for route in present):
            block(CLASSIFICATION_UNKNOWN, f"{prefix} is installed by a source this workflow does not know")
        elif not _owned_by(routes, prefix, transition.old):
            block(OLD_ROUTE_ABSENT, f"{prefix} is not installed by {transition.old.source} via {transition.old.interface}")
    hop = ipaddress.ip_address(transition.shield_next_hop)
    attached = [route for route in routes if _kind(route) == "connected" and hop in ipaddress.ip_network(route["prefix"])]
    best = max(attached, key=lambda route: ipaddress.ip_network(route["prefix"]).prefixlen, default=None)
    resolving = [route for route in routes if hop in ipaddress.ip_network(route["prefix"])]
    longest = max(resolving, key=lambda route: ipaddress.ip_network(route["prefix"]).prefixlen, default=None)
    if longest is not None and any(_is_management(name) for name in longest.get("interfaces", ())):
        block(MANAGEMENT_FALLBACK, f"the shield next hop {hop} resolves through the management interface")
    if best is None or transition.shield_interface not in best.get("interfaces", ()):
        block(NEXT_HOP_UNHEALTHY, f"{hop} is not directly connected on {transition.shield_interface}")
    elif (interfaces.get(transition.shield_interface) or {}).get("oper") != "UP":
        block(NEXT_HOP_UNHEALTHY, f"{transition.shield_interface} is not up")
    elif next_hop_alive is None or not next_hop_alive(transition.device, str(hop)):
        block(NEXT_HOP_UNHEALTHY, f"{hop} does not answer")
    for cover in transition.shield_prefixes:
        if _routes(routes, cover):
            block(OUT_OF_BAND, f"a route for the shield prefix {cover} already exists")
        if transition.shield_kind == model.LESS_SPECIFIC:
            network = ipaddress.ip_network(cover)
            foreign = [route["prefix"] for route in routes if route["prefix"] not in {str(ipaddress.ip_network(p)) for p in transition.protected}
                       and ipaddress.ip_network(route["prefix"]).version == 6 and ipaddress.ip_network(route["prefix"]).subnet_of(network)
                       and route["prefix"] != str(network)]
            if foreign:
                block(CLASSIFICATION_UNKNOWN, f"the cover {cover} would also catch {', '.join(sorted(foreign))}")
    if transition.new.source == model.ISIS:
        if not any(row.get("interface") == transition.new.interface and row.get("state") == "UP" for row in isis):
            block(NEW_PATH_UNAVAILABLE, f"no IS-IS adjacency is up on {transition.new.interface}")
        elif transition.old.source != model.ISIS and (new_route_available is None or not new_route_available(transition)):
            block(NEW_PATH_UNAVAILABLE, "IS-IS does not hold the protected prefixes yet")
    elif (interfaces.get(transition.new.interface) or {}).get("oper") != "UP":
        block(NEW_PATH_UNAVAILABLE, f"{transition.new.interface} is not up")
    return found


def default_host_gate(*, max_load_per_cpu: float = 4.5, min_available_mb: int = 4096, max_swap_used_mb: int = 512):
    """The host that runs the devices must not be starved: a loaded host widens the replacement gap.  Returns (ok, facts)."""
    try:
        load = float(open("/proc/loadavg").read().split()[0])
        meminfo = {line.split(":")[0]: int(line.split()[1]) for line in open("/proc/meminfo") if ":" in line}
    except (OSError, ValueError, IndexError):
        return False, {"error": "host facts unreadable"}
    facts = {"load1": load, "cpus": os.cpu_count() or 1, "available_mb": meminfo.get("MemAvailable", 0) // 1024,
             "swap_used_mb": (meminfo.get("SwapTotal", 0) - meminfo.get("SwapFree", 0)) // 1024}
    ok = load <= max_load_per_cpu * facts["cpus"] and facts["available_mb"] >= min_available_mb and facts["swap_used_mb"] <= max_swap_used_mb
    return ok, facts


# -- the migration window ---------------------------------------------------------------------------------------------------
# Measured on this host on 2026-10-12 (UTC) with the Challenge Console stopped, no disposable lab and no test run (the state a
# window requires): docs/evidence/v2-route-shield/closure/host_baseline.json.  The gate is that measurement plus a margin,
# not a general rule about load averages.  A re-measurement is a reviewed change of these two numbers.
QUIET_LOAD1_MAX_MEASURED = 6.06
QUIET_LOAD_MARGIN = 1.5
# matched against the START of a process's own command line (its interpreter), never against text that merely mentions one
WINDOW_FORBIDDEN_PROCESSES = ((r"\S*python\S* (\S+ )*-m challenge_console\b", "the Challenge Console is running"),
                              (r"\S*python\S* (\S+ )*manage\.py test\b", "a Django test run is in progress"),
                              (r"(\S*python\S* (\S+ )*-m pytest\b|\S*pytest( |$))", "a test run is in progress"),
                              (r"\S*python\S* (\S+ )*tier3\.py\b", "a Tier-3 run is in progress"))
WINDOW_FORBIDDEN_CONTAINERS = ("isisbx-", "clab-nmas-cap-validation-")
CPU_POLICY_FILE = "monitoring/config/cpu_threshold_policy.yml"


def _processes() -> list[str]:
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit() and int(entry) != os.getpid():
            try:
                found.append(open(f"/proc/{entry}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace"))
            except OSError:
                continue
    return found


def _containers() -> list[str]:
    import subprocess

    done = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=20, check=False)  # noqa: S603,S607
    if done.returncode:
        raise OSError("docker ps failed")
    return done.stdout.split()


def _cpu_busy_percent(seconds: float = 5.0) -> float:
    import time

    def sample():
        parts = [int(v) for v in open("/proc/stat").readline().split()[1:9]]
        return sum(parts), parts[3] + parts[4]

    total_a, idle_a = sample()
    time.sleep(seconds)
    total_b, idle_b = sample()
    return round(100.0 * (1 - (idle_b - idle_a) / max(1, total_b - total_a)), 1)


def _cpu_warning_percent() -> float:
    import yaml
    from django.conf import settings

    with open(os.path.join(str(settings.REPO_ROOT), CPU_POLICY_FILE), encoding="utf-8") as handle:
        return float((yaml.safe_load(handle) or {})["warning_pct"])


def _cpu_policy() -> dict:
    import yaml
    from django.conf import settings

    with open(os.path.join(str(settings.REPO_ROOT), CPU_POLICY_FILE), encoding="utf-8") as handle:
        policy = yaml.safe_load(handle) or {}
    return {"warning": float(policy["warning_pct"]), "critical": float(policy["critical_pct"])}


def cpu_consecutive_samples() -> int:
    """How many consecutive samples the project's CPU policy needs before a level is a condition and not a spike."""
    import yaml
    from django.conf import settings

    with open(os.path.join(str(settings.REPO_ROOT), CPU_POLICY_FILE), encoding="utf-8") as handle:
        return max(1, int((yaml.safe_load(handle) or {})["consecutive_samples"]))


def window_host_gate(*, probes_running: bool = False, processes=_processes, containers=_containers, cpu_busy=_cpu_busy_percent,
                     cpu_warning=_cpu_warning_percent, cpu_policy=_cpu_policy, loadavg="/proc/loadavg", meminfo="/proc/meminfo"):
    """The resource gate of a PRODUCTION window.  -> (ok, facts); ``facts["failed"]`` names every reason.

    QUIET (``probes_running`` false, evaluated before the dedicated probes start): console stopped, no disposable lab,
    no test run, no swap in use, host CPU below the project's own CPU WARNING threshold, load averages within the
    measured quiet baseline of this host.

    PROBED (``probes_running`` true, every later evaluation): the same, except that the probes themselves are a
    measured load (CPU 80 to 84 %, load rising past 17: closure/host_probes.json), so CPU is held below the policy's
    CRITICAL threshold and the load averages are reported, not judged."""
    facts: dict = {"failed": []}
    try:
        load1, load5 = (float(v) for v in open(loadavg).read().split()[:2])
        memory = {line.split(":")[0]: int(line.split()[1]) for line in open(meminfo) if ":" in line}
        limit = round(QUIET_LOAD1_MAX_MEASURED * QUIET_LOAD_MARGIN, 2)
        facts.update(load1=load1, load5=load5, load_limit=limit, measured_quiet_load1_max=QUIET_LOAD1_MAX_MEASURED,
                     swap_used_mb=(memory.get("SwapTotal", 0) - memory.get("SwapFree", 0)) // 1024,
                     available_mb=memory.get("MemAvailable", 0) // 1024, cpu_busy_percent=cpu_busy(), cpu_warning_percent=cpu_warning(),
                     phase="PROBED" if probes_running else "QUIET")
        if probes_running:
            facts["cpu_critical_percent"] = cpu_policy()["critical"]
        running, names = processes(), containers()
    except (OSError, ValueError, IndexError, KeyError, TypeError):
        return False, {"failed": ["host facts unreadable"]}
    for needle, reason in WINDOW_FORBIDDEN_PROCESSES:
        if any(re.match(needle, line) for line in running):
            facts["failed"].append(reason)
    labs = sorted(name for name in names if name.startswith(WINDOW_FORBIDDEN_CONTAINERS))
    if labs:
        facts["failed"].append(f"a disposable lab exists ({labs[0]} and {len(labs) - 1} more)")
    if facts["swap_used_mb"] > 0:
        facts["failed"].append(f"swap is in use ({facts['swap_used_mb']} MB)")
    if facts["available_mb"] < 4096:
        facts["failed"].append("less than 4 GB of memory is available")
    if probes_running:
        if facts["cpu_busy_percent"] >= facts["cpu_critical_percent"]:
            facts["failed"].append(f"host CPU is at {facts['cpu_busy_percent']}% with the probes running, the critical threshold is {facts['cpu_critical_percent']}%")
        return not facts["failed"], facts
    if facts["cpu_busy_percent"] >= facts["cpu_warning_percent"]:
        facts["failed"].append(f"host CPU is at {facts['cpu_busy_percent']}%, the warning threshold is {facts['cpu_warning_percent']}%")
    if load1 > limit or load5 > limit:
        facts["failed"].append(f"load {load1}/{load5} is above the measured quiet baseline limit {limit}")
    return not facts["failed"], facts


class WindowGate:
    """The host gate of one production command.  ``measure_quiet()`` is called once, BEFORE the probes start; every
    later call (the precheck, and the precheck again inside the lock) is the PROBED gate and also requires that the
    quiet gate passed.  A command that never measured the quiet host is refused."""

    def __init__(self, gate=window_host_gate, consecutive_samples=cpu_consecutive_samples):
        self._gate, self.quiet, self.consecutive_samples = gate, None, consecutive_samples

    def measure_quiet(self):
        self.quiet = self._gate(probes_running=False)
        return self.quiet

    def __call__(self):
        if self.quiet is None:
            return False, {"failed": ["the quiet-host gate was not evaluated before the probes started"]}
        ok, facts = self._gate(probes_running=True)
        facts = {**facts, "quiet": self.quiet[1], "failed": [*self.quiet[1].get("failed", []), *facts.get("failed", [])]}
        return not facts["failed"], facts
