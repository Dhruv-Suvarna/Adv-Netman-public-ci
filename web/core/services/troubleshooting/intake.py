"""Unattended incident intake: monitoring observation -> deterministic classification -> correlated incident -> case -> Codex.

Detection is read-only.  Each pass reads every in-scope managed device's interfaces (cEOS ``show interfaces | json``:
administrative vs operational state, the device's own link-transition counter, error/discard counters) and, every
``routing_every`` passes, its OSPF/BGP neighbors.  ``faults`` classifies each interface against the authoritative intent
(``hc._intended_admin_states``) and its bounded history:

- ADMIN_STATE_MISMATCH       admin down, intent up                      (confirmed after ``confirm_seconds``)
- OPERATIONAL_LINK_DOWN      admin UP, oper down                        (persisting >= ``confirm_seconds``)
- LINK_FLAPPING              >= faults.FLAP_MIN_TRANSITIONS in the window (poll edges and device counter), admin up
- INTERFACE_DEGRADATION      error/discard deltas over threshold in consecutive intervals (counter resets excluded)
- ROUTING_ADJACENCY_FAILURE  an expected OSPFv2 / OSPFv3 / BGP-IPv4 / BGP-IPv6 adjacency absent/not FULL|Established for
                             >= ``confirm_seconds``; a loss on a device with a concurrent link incident is recorded on that
                             incident as a secondary symptom, not a new case
- ROUTE_OR_REACHABILITY_FAILURE (SOURCE_COLLAPSE)  a learned dynamic route source (RIP, OSPF, OSPF externals = redistributed
                             routes, OSPFv3, IS-IS, BGP; IPv4 and IPv6 route summaries) lost at least half its routes for
                             >= ``confirm_seconds``; secondary to a concurrent link or adjacency incident on the same device.
                             The expectation is a LEARNED baseline (counts seen healthy by this process), never intent

Correlation: the two ends of one topology link are ONE incident (fingerprint ``LINK:a|b``, else ``IFACE:dev:if``; adjacencies
``ADJ:dev:proto:neighbor``).  The case is scoped to the administratively-disabled side for an admin mismatch (unchanged
from campaign 011), otherwise to both readable ends.

Every opened case carries the structured observations (``faults.EVIDENCE_KEY``), the deterministic classification and the
deterministic remediation decision (``REMEDIATION_DECISION`` audit) BEFORE any model call, so a Codex outage never loses
the fault.  Non-remediable outcomes are escalated by email (safe non-remediation).

Safety (unchanged): at most one open case per fingerprint; a per-fingerprint cooldown; a global hourly case budget; idempotency
keys; the system identity ``nmas-intake``; no device write and no approval, ever.  New: maintenance suppression (auditable
reason), bounded transition history, dispatch retry while the AI path is unavailable, and verified closure of escalated cases
whose fault cleared without NMAS acting (``UNRESOLVED`` with ``cleared_externally``; NMAS never claims the repair).
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
import secrets
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from django.conf import settings

from ... import models
from . import faults
from . import notify
from . import repository as repo
from . import route_intent
from . import routing
from .runbooks import hc

log = logging.getLogger("nmas.ts.intake")

ACTOR_NAME = "nmas-intake"
TRIGGER_SOURCE = "monitoring"
HANDOFF_ID = re.compile(r"^AIH-[0-9a-f]{12}$")
DEFAULT_DEVICES = ("R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4", "mgmt_swt")
DEFAULT_ROUTING_DEVICES = ("R1", "R2", "R3", "R4", "R5", "S1", "S2")   # S1/S2: RIP + IS-IS; R3/R4: FRR (ospfd/ospf6d/bgpd)
FRR_DEVICES = frozenset({"R3", "R4"})
INCIDENT_CATEGORIES = (faults.ADMIN_STATE_MISMATCH, faults.OPERATIONAL_LINK_DOWN, faults.LINK_FLAPPING, faults.INTERFACE_DEGRADATION)
ADJ_SECONDARY_GRACE_S = 300           # an adjacency loss this close to a link incident on the same device is treated as secondary
DISPATCH_RETRY_SECONDS = 120
DISPATCH_RETRY_MAX = 15
IN_FLIGHT_PLAN_STATES = ("DRY_RUN_PASS", "APPROVED", "PREAUTHORIZED", "PRECHECK_PASS", "EXECUTING", "VERIFYING")


@dataclass(frozen=True)
class Observation:
    """Legacy status row (``show interfaces status``); still accepted from readers and converted to an InterfaceSample."""
    device: str
    interface: str
    link: str            # cEOS linkStatus: connected | notconnect | disabled | errdisabled | ...
    protocol: str        # lineProtocolStatus: up | down | ...


@dataclass
class IntakeConfig:
    devices: tuple[str, ...] = DEFAULT_DEVICES
    confirm_seconds: int = 30
    cooldown_seconds: int = 900
    max_cases_per_hour: int = 4
    container_prefix: str = "clab-srlceos01-"
    fingerprint_prefix: str = ""          # "REPLAY:" for controlled replays, so they never cool down a live fingerprint
    routing_devices: tuple[str, ...] = ()
    routing_every: int = 3                # read adjacencies every N passes
    verify_clear: bool = True
    route_intent_path: str = ""           # explicit reviewed source; empty preserves the existing intake
    topology_revision: str = ""           # trusted active-inventory revision, never inferred from an observed RIB
    route_intent_max_age_seconds: int = 60

    @classmethod
    def from_settings(cls) -> "IntakeConfig":
        def names(key, default):
            raw = getattr(settings, key, None)
            if raw is None:
                return default
            return tuple(d.strip() for d in str(raw).split(",") if d.strip())
        return cls(devices=names("NMAS_TS_INTAKE_DEVICES", "") or DEFAULT_DEVICES,
                   confirm_seconds=int(getattr(settings, "NMAS_TS_INTAKE_CONFIRM_SECONDS", 30)),
                   cooldown_seconds=int(getattr(settings, "NMAS_TS_INTAKE_COOLDOWN_SECONDS", 900)),
                   max_cases_per_hour=int(getattr(settings, "NMAS_TS_INTAKE_MAX_CASES_PER_HOUR", 4)),
                   routing_devices=names("NMAS_TS_INTAKE_ROUTING_DEVICES", DEFAULT_ROUTING_DEVICES),
                   route_intent_path=str(getattr(settings, "NMAS_TS_ROUTE_INTENT_FILE", "") or ""),
                   topology_revision=str(getattr(settings, "NMAS_TS_TOPOLOGY_REVISION", "") or ""),
                   route_intent_max_age_seconds=int(getattr(settings, "NMAS_TS_ROUTE_INTENT_MAX_AGE_SECONDS", 60)))


# ------------------------------------------------------------------------------------------------------------- observation
def _cli_json(container: str, command: str) -> dict | None:
    argv = ["docker", "exec", container, "Cli", "-p", "15", "-c", f"{command} | json"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
        return json.loads(out.stdout) if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def read_device(device: str, cfg: IntakeConfig) -> list[faults.InterfaceSample] | None:
    """Read-only interface state + counters of one managed device (the same console read path the recovery service uses)."""
    if device in FRR_DEVICES:
        try:
            out = subprocess.run(["docker", "exec", f"{cfg.container_prefix}{device}", "ip", "-j", "-s", "link", "show"],
                                 capture_output=True, text=True, timeout=20, check=False)
            links = json.loads(out.stdout) if out.returncode == 0 else None
        except (OSError, subprocess.SubprocessError, ValueError):
            links = None
        return None if not isinstance(links, list) else faults.linux_interface_samples(device, links, datetime.now(timezone.utc))
    doc = _cli_json(f"{cfg.container_prefix}{device}", "show interfaces")
    if doc is None or not isinstance(doc.get("interfaces"), dict):
        return None
    return faults.interface_samples(device, doc, datetime.now(timezone.utc))


ADJACENCY_COMMANDS = {"ospf": "show ip ospf neighbor", "ospf3": "show ipv6 ospf neighbor",
                      "bgp": "show ip bgp summary", "bgp6": "show ipv6 bgp summary"}


def _vtysh_json(container: str, command: str) -> dict | None:
    """Read-only FRR query through the trusted Containerlab console (``vtysh -c 'show ... json'``)."""
    argv = ["docker", "exec", container, "vtysh", "-c", f"{command} json"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
        return json.loads(out.stdout) if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _frr_route_counts(doc: dict | None, af: str) -> dict[str, int] | None:
    """FRR ``show ip[v6] route json`` -> the same normalised source counts as the cEOS summaries (selected routes only)."""
    if not isinstance(doc, dict):
        return None
    rows = {}
    for prefix, entries in doc.items():
        best = next((e for e in entries if e.get("selected")), None) if isinstance(entries, list) else None
        if best:
            rows[prefix] = routing.RibEntry(prefix, routing._LINUX_SOURCES.get(best.get("protocol", ""), best.get("protocol", "")), "", (), af)  # pylint: disable=protected-access
    if af == "ipv6":
        rows = {k: routing.RibEntry(k, routing._V6_RENAME.get(v.source, v.source), "", (), af) for k, v in rows.items()}  # pylint: disable=protected-access
    counts = routing.source_counts(rows)
    return {k: int(counts.get(k, 0)) for k in ("bgp", "connected", "isis", "ospf", "ospf3", "rip", "static")}


def read_adjacencies(device: str, cfg: IntakeConfig) -> list[faults.AdjacencySample] | None:
    container = f"{cfg.container_prefix}{device}"
    if device in FRR_DEVICES:
        docs = {"ospf": _vtysh_json(container, "show ip ospf neighbor"), "ospf6": _vtysh_json(container, "show ipv6 ospf6 neighbor"),
                "bgp": _vtysh_json(container, "show bgp summary")}
        if all(d is None for d in docs.values()):
            return None
        return routing.frr_adjacency_samples(device, docs, datetime.now(timezone.utc))
    docs = {key: _cli_json(container, cmd) for key, cmd in ADJACENCY_COMMANDS.items()}
    if all(d is None for d in docs.values()):
        return None
    return routing.ceos_adjacency_samples(device, docs, datetime.now(timezone.utc))


def read_route_sources(device: str, cfg: IntakeConfig) -> dict[str, dict[str, int] | None] | None:
    """Normalised per-protocol route counts from the IPv4 and IPv6 route summaries (two small read-only documents)."""
    container = f"{cfg.container_prefix}{device}"
    if device in FRR_DEVICES:
        out = {"ipv4": _frr_route_counts(_vtysh_json(container, "show ip route"), "ipv4"),
               "ipv6": _frr_route_counts(_vtysh_json(container, "show ipv6 route"), "ipv6")}
        return None if all(v is None for v in out.values()) else out
    out = {"ipv4": routing.ceos_summary_counts(_cli_json(container, "show ip route summary"), "ipv4"),
           "ipv6": routing.ceos_summary_counts(_cli_json(container, "show ipv6 route summary"), "ipv6")}
    return None if all(v is None for v in out.values()) else out


# ----------------------------------------------------------------------------------------------- topology-wide path evidence
RIB_DEVICES = ("R1", "R2", "R3", "R4", "R5", "S1", "S2", "H1")
ADDRESS_DEVICES = RIB_DEVICES + ("S3", "S4", "mgmt_swt", "H2", "H3", "H4", "WebServer")
LINUX_NODES = frozenset({"R3", "R4", "H1", "H2", "H3", "H4", "WebServer"})
TOPOLOGY_FLOWS = (   # (name, source, destination, family, class)
    ("H1-H2-v4", "H1", "192.168.20.101", "ipv4", "protected"),
    ("H1-H2-v6", "H1", "2001:db8:20::2001", "ipv6", "protected"),
    ("H1-WEB-v4", "H1", "172.30.50.10", "ipv4", "service"),
    ("H1-WEB-v6", "H1", "2001:db8:3050::10", "ipv6", "service"),
)


def _docker_json(argv: list[str]):
    try:
        out = subprocess.run(["docker", "exec", *argv], capture_output=True, text=True, timeout=20, check=False)
        return json.loads(out.stdout) if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def topology_snapshot(cfg: IntakeConfig) -> dict:
    """Read-only RIB / address snapshot of the managed topology through the trusted console (the intake's read channel)."""
    import yaml
    from pathlib import Path

    ribs4, ribs6, addresses, unreadable = {}, {}, {}, []
    for dev in ADDRESS_DEVICES:
        c = f"{cfg.container_prefix}{dev}"
        if dev in LINUX_NODES:
            addresses[dev] = routing.linux_addresses(_docker_json([c, "ip", "-j", "addr", "show"]))
            if dev in RIB_DEVICES:
                ribs4[dev] = routing.linux_rib(_docker_json([c, "ip", "-j", "-4", "route", "show"]), "ipv4")
                ribs6[dev] = routing.linux_rib(_docker_json([c, "ip", "-j", "-6", "route", "show"]), "ipv6")
        else:
            addresses[dev] = routing.ceos_addresses(_cli_json(c, "show ip interface brief"), _cli_json(c, "show ipv6 interface brief"))
            if dev in RIB_DEVICES:
                ribs4[dev] = routing.ceos_rib(_cli_json(c, "show ip route"))
                ribs6[dev] = routing.ceos_rib(_cli_json(c, "show ipv6 route"))
        if not addresses[dev] or (dev in RIB_DEVICES and (ribs4.get(dev) is None or ribs6.get(dev) is None)):
            unreadable.append(dev)
    links = routing.clab_links(yaml.safe_load((Path(settings.REPO_ROOT) / "srlceos01.clab.yml").read_text(encoding="utf-8")))
    return {"ribs4": ribs4, "ribs6": ribs6, "addresses": addresses, "links": links, "unreadable": sorted(set(unreadable)),
            "collected_at": datetime.now(timezone.utc).isoformat()}


def read_route_intent_ribs(intent: route_intent.RouteIntent, cfg: IntakeConfig) -> dict:
    """Collect only the RIBs named by reviewed intent through the intake's existing read-only console channel.

    The active topology revision is supplied independently by deployment configuration.  It is deliberately not learned
    from these observations.  A failed family read remains ``None`` so evaluation is INDETERMINATE, never MISSING_ROUTE.
    """
    devices = sorted({item.device for item in intent.expectations})
    ribs = {"ipv4": {}, "ipv6": {}}
    observed = {}
    for device in devices:
        container = f"{cfg.container_prefix}{device}"
        if device in LINUX_NODES:
            ribs["ipv4"][device] = routing.linux_rib(
                _docker_json([container, "ip", "-j", "-4", "route", "show"]), "ipv4",
            )
            ribs["ipv6"][device] = routing.linux_rib(
                _docker_json([container, "ip", "-j", "-6", "route", "show"]), "ipv6",
            )
        else:
            ribs["ipv4"][device] = routing.ceos_rib(_cli_json(container, "show ip route"))
            ribs["ipv6"][device] = routing.ceos_rib(_cli_json(container, "show ipv6 route"))
        observed[device] = datetime.now(timezone.utc).isoformat()
    collected = datetime.now(timezone.utc).isoformat()
    return {"ribs": ribs, "observed_at": collected, "device_observed_at": observed,
            "collector": "nmas-intake trusted-console-read-only"}


ROUTE_INTENT_PASS_SCHEMA = "nmas.troubleshooting.route-intent-pass/1"
ROUTE_INTENT_CASE_SCHEMA = "nmas.troubleshooting.route-intent-case/1"
ROUTE_INTENT_SEVERITY = {"HEALTHY": "info", "DEGRADED": "warning", "INDETERMINATE": "warning", "REFUSED": "error", "ERROR": "error"}
ROUTE_INTENT_MAX_ITEMS = 32


def route_intent_pass_record(row: dict, *, pass_id: str, at: datetime, results: list | None = None, expectations: int = 0,
                             confirmed: frozenset = frozenset()) -> dict:
    """One structured, journal-safe record per evaluated route-intent pass.

    Carries the pass correlation id, the evaluated route counts by classification, every non-healthy (target, device, prefix)
    item with its intake fingerprint, and a stable ``error_code``.  It never carries observed next hops, RIB documents,
    console output or credentials; the full per-route evidence is stored on the case, keyed by the same ``pass_id``.
    """
    state = str(row.get("route_intent") or "ERROR")
    reason = str(row.get("reason") or "")
    code = reason.split(":", 1)[0] if reason else None
    if code is None and state == "INDETERMINATE":
        code = "RIB_ENTRIES_INDETERMINATE"
    rec = {"schema": ROUTE_INTENT_PASS_SCHEMA, "event": "route_intent_pass", "pass_id": pass_id,
           "at": at.astimezone(timezone.utc).isoformat(), "state": state,
           "severity": ROUTE_INTENT_SEVERITY.get(state, "error"), "error_code": code, **row}
    if results is not None:
        by_category = Counter(r.category for r in results)
        items = []
        for r in results:
            if r.category == faults.NO_FAULT:
                continue
            fp = f"RINT:{row.get('intent_revision', '-')}:{r.scope.get('target_id', '-')}:{r.scope.get('device', '-')}"
            items.append({"target_id": r.scope.get("target_id"), "direction": r.scope.get("direction"),
                          "device": r.scope.get("device"), "af": r.scope.get("af"),
                          "route_prefix": r.evidence.get("route_prefix"), "category": r.category,
                          "status": ("INDETERMINATE" if r.category == faults.INDETERMINATE else
                                     "CONFIRMED" if fp in confirmed else "PENDING_CONFIRMATION"),
                          "fingerprint": fp})
        rec["routes"] = {"expected": expectations, "evaluated": len(results),
                         "devices": len({r.scope.get("device") for r in results}),
                         "by_category": dict(sorted(by_category.items()))}
        rec["items"] = items[:ROUTE_INTENT_MAX_ITEMS]
        rec["items_truncated"] = max(0, len(items) - ROUTE_INTENT_MAX_ITEMS)
        rec["confirmed_fingerprints"] = sorted(confirmed)
    return rec


ROUTE_INTENT_ENV = ("NMAS_TS_ROUTE_INTENT_FILE", "NMAS_TS_TOPOLOGY_REVISION", "NMAS_TS_ROUTE_INTENT_MAX_AGE_SECONDS")


def unit_route_intent_binding(reader=None) -> dict:
    """The route-intent binding of the *running* intake unit (its Environment=), not of this shell's settings."""
    def show() -> str:
        return subprocess.run(["systemctl", "show", "nmas-ts-intake.service", "-p", "Environment", "--value"],
                              capture_output=True, text=True, timeout=10, check=False).stdout
    try:
        raw = (reader or show)()
    except (OSError, subprocess.SubprocessError):
        return {"bound": False, "error_code": "UNIT_ENVIRONMENT_UNAVAILABLE"}
    env = dict(item.split("=", 1) for item in raw.split() if "=" in item and item.split("=", 1)[0] in ROUTE_INTENT_ENV)
    return {"bound": bool(env.get("NMAS_TS_ROUTE_INTENT_FILE")), "intent_file": env.get("NMAS_TS_ROUTE_INTENT_FILE", ""),
            "topology_revision": env.get("NMAS_TS_TOPOLOGY_REVISION", ""),
            "max_age_seconds": env.get("NMAS_TS_ROUTE_INTENT_MAX_AGE_SECONDS", "")}


def route_intent_case_record(incident: "Incident", opened: dict | None, at: datetime, *, error: str = "") -> dict:
    """Correlates a confirmed route-intent fault (journal ``pass_id``/fingerprint) with the case and handoff it opened."""
    doc = incident.route_evidence or {}
    cls = incident.classification
    return {"schema": ROUTE_INTENT_CASE_SCHEMA, "event": "route_intent_case", "pass_id": doc.get("pass_id", ""),
            "at": at.astimezone(timezone.utc).isoformat(), "severity": "error" if error else "warning",
            "error_code": "ROUTE_INTENT_CASE_OPEN_FAILED" if error else None, "exception": error or None,
            "fingerprint": incident.fingerprint, "case_id": (opened or {}).get("case"), "handoff_id": (opened or {}).get("handoff"),
            "dispatch_started": (opened or {}).get("dispatch_started"),
            "intent_revision": doc.get("intent_revision"), "topology_revision": doc.get("topology_revision"),
            "category": cls.category if cls else None,
            "decision": (incident.decision or {}).get("outcome"),
            "target_id": cls.scope.get("target_id") if cls else None, "device": incident.devices[0] if incident.devices else None,
            "route_prefix": cls.evidence.get("route_prefix") if cls else None}


def _kernel(device: str, interface: str) -> str:
    m = re.fullmatch(r"Ethernet(\d+)", interface or "")
    return f"eth{m.group(1)}" if m else interface


def flow_paths(snapshot: dict, incident_ports: set[tuple[str, str]]) -> list[dict]:
    """Every ECMP branch of every topology flow, marked when it egresses an incident interface (either end)."""
    out = []
    for name, src, dst, af, klass in TOPOLOGY_FLOWS:
        ribs = snapshot["ribs6" if af == "ipv6" else "ribs4"]
        allp = routing.reconstruct_all_paths(src, dst, ribs, snapshot["addresses"], links=snapshot["links"])
        for i, br in enumerate(allp["branches"]):
            hops = br.get("hops", [])
            hits = [f"{h['device']}:{h.get('egress', '')}" for h in hops
                    if (h["device"], _kernel(h["device"], h.get("egress", ""))) in incident_ports]
            out.append({"flow": name, "class": klass, "source": src, "destination": dst, "af": af, "branch": i + 1,
                        "branches": len(allp["branches"]), "verdict": br["verdict"], "overall": allp["verdict"],
                        "reason": br.get("reason", ""), "delivered_to": br.get("delivered_to", ""),
                        "hops": [{"device": h["device"], "prefix": h["prefix"], "source": h["source"], "egress": h.get("egress", ""),
                                  "next_device": h.get("next_device") or ""} for h in hops],
                        "traverses_incident": hits})
    return out


def record_topology_paths(actor, case, incident: "Incident", cfg: IntakeConfig, now: datetime, *, snapshot: dict | None = None) -> list[str]:
    """Persist the topology-wide forwarding-path evidence of an incident (CORRELATE stage).  Read-only; failures are audited."""
    snapshot = snapshot or topology_snapshot(cfg)
    ports = {(s.device, _kernel(s.device, s.interface)) for s in (incident.samples or incident.members)}
    rows = flow_paths(snapshot, ports)
    ev = repo.store_evidence(actor, case, source_type="topology_paths", device=(incident.devices or ["-"])[0],
                             command_or_api="RIB + interface addresses via trusted console (read-only; RIB is not a validated FIB)",
                             adapter="nmas-intake", parser="routing.reconstruct_all_paths", parser_version="1",
                             collected_at=now, raw=json.dumps({"paths": rows, "unreadable": snapshot["unreadable"],
                                                               "collected_at": snapshot["collected_at"]}, sort_keys=True))
    ids = []
    for row in rows:
        rec = repo.record(actor, case, "topology_path", basis="OBSERVED", evidence_ids=[ev.evidence_id], now=now,
                          source=row["source"], destination=row["destination"], address_family=row["af"],
                          service=f"{row['flow']} ({row['class']})", observed_hops=row["hops"],
                          links=[f"{h['device']}:{h['egress']}->{h['next_device']}" for h in row["hops"] if h["next_device"]],
                          next_hops=[h["next_device"] for h in row["hops"] if h["next_device"]],
                          lookup_provenance={"method": "hop-by-hop RIB longest-prefix match", "branch": f"{row['branch']}/{row['branches']}",
                                             "verdict": row["verdict"], "overall": row["overall"], "reason": row["reason"],
                                             "rib_is_not_fib": True, "unreadable_devices": snapshot["unreadable"]},
                          divergence=[f"egresses incident interface {h}" for h in row["traverses_incident"]])
        ids.append(rec.record_id)
    affected = sorted({r["flow"] for r in rows if r["traverses_incident"] or r["overall"] in (routing.BLACKHOLE, routing.LOOP)})
    repo.audit(actor, case, "TOPOLOGY_PATHS", decision=(f"{len(rows)} path branch(es) over {len(TOPOLOGY_FLOWS)} flows; "
                                                       f"affected: {', '.join(affected) or 'none'}")[:255],
               result="AFFECTED" if affected else "UNAFFECTED", evidence_ids=[ev.evidence_id], now=now,
               rationale=json.dumps({"incident_ports": sorted(f"{d}:{i}" for d, i in ports), "unreadable": snapshot["unreadable"]})[:3000])
    return ids


def _as_sample(row: Any, now: datetime) -> faults.InterfaceSample:
    if isinstance(row, faults.InterfaceSample):
        return row
    return faults.InterfaceSample(device=row.device, interface=row.interface, at=now, admin="down" if row.link == "disabled" else "up",
                                  oper="up" if row.link == "connected" and row.protocol == "up" else "down", link_status=row.link,
                                  protocol=row.protocol, source="ceos:show interfaces status | json")


def violations(observations: list, intent: Callable[[str], dict | None]) -> dict[tuple[str, str], Any]:
    """Interfaces whose authoritative intent is up but which are not connected/up (kept for ``--observe``)."""
    out: dict[tuple[str, str], Any] = {}
    cache: dict[str, dict] = {}
    now = datetime.now(timezone.utc)
    for ob in observations:
        s = _as_sample(ob, now)
        if s.interface.startswith("Management"):
            continue
        want = cache.setdefault(s.device, intent(s.device) or {})
        if want.get(s.interface) == "up" and (s.admin != "up" or s.oper != "up"):
            out[(s.device, s.interface)] = ob
    return out


def peers(devices: set[str]) -> dict[tuple[str, str], tuple[str, str]]:
    """Link peers from the tracked Containerlab topology (cEOS ``ethN`` == ``EthernetN``)."""
    from .intake_scope import _links

    def name(device: str, iface: str) -> str:
        m = re.fullmatch(r"eth(\d+)", iface)
        return f"Ethernet{m.group(1)}" if m and device not in FRR_DEVICES else iface     # Linux/FRR keeps its kernel name

    out = {}
    for row in _links(devices):
        s = row["scope"]
        a, b = (s["a"], name(s["a"], s["a_if"])), (s["b"], name(s["b"], s["b_if"]))
        out[a], out[b] = b, a
    return out


@dataclass
class Incident:
    fingerprint: str
    devices: list[str]                       # case scope
    members: list[faults.InterfaceSample]
    onset: datetime
    classification: faults.Classification | None = None
    decision: dict | None = None
    samples: list[faults.InterfaceSample] = field(default_factory=list)    # every end (incl. healthy far end) for evidence
    secondary: list[str] = field(default_factory=list)
    route_evidence: dict | None = None

    @property
    def category(self) -> str:
        return self.classification.category if self.classification else faults.ADMIN_STATE_MISMATCH

    def symptom(self) -> str:
        seen = "; ".join(f"{o.device} {o.interface} link={o.link_status} protocol={o.protocol}" for o in self.members)
        if not seen and self.classification is not None:
            return (f"Monitoring alarm (automatic intake): {self.category}. Deterministic classification: "
                    f"{self.classification.summary}.")[:4000]
        head = ("Monitoring alarm (automatic intake): interface state deviates from intended up state for >= confirmation window. "
                if self.category in (faults.ADMIN_STATE_MISMATCH, faults.OPERATIONAL_LINK_DOWN) else
                f"Monitoring alarm (automatic intake): {self.category}. ")
        tail = f" Deterministic classification: {self.category} - {self.classification.summary}." if self.classification else ""
        return f"{head}Observed: {seen}.{tail}"[:4000]


def correlate(current: dict, link_peers: dict, onset: dict, *, classes: dict | None = None, samples: dict | None = None) -> list[Incident]:
    """Group abnormal interface ends into incidents (both ends of one link == one incident)."""
    out, done = [], set()
    classes, samples = classes or {}, samples or {}
    for key in sorted(current):
        if key in done:
            continue
        peer = link_peers.get(key)
        members = [current[key]] + ([current[peer]] if peer in current else [])
        members = [_as_sample(m, onset.get((m.device, m.interface), datetime.now(timezone.utc))) for m in members]
        done.update((o.device, o.interface) for o in members)
        ends = sorted([key, peer]) if peer else [key]
        fp = "LINK:" + "|".join(f"{d}:{i}" for d, i in ends) if peer else f"IFACE:{key[0]}:{key[1]}"
        end_classes = [classes[e] for e in ends if e in classes]
        cl = faults.classify_link(end_classes) if end_classes else None
        disabled = sorted({o.device for o in members if o.link_status in ("disabled",)})
        readable = sorted({e[0] for e in ends if e in samples})
        if cl is None or cl.category == faults.ADMIN_STATE_MISMATCH:
            devices = disabled or sorted({o.device for o in members})
        else:
            devices = readable or sorted({o.device for o in members})
        out.append(Incident(fp, devices, members, min(onset[(o.device, o.interface)] for o in members), classification=cl,
                            samples=[samples[e] for e in ends if e in samples]))
    return out


# -------------------------------------------------------------------------------------------------------------- case intake
def _open_for(fp: str):
    return models.TsCase.objects.filter(trigger_source=TRIGGER_SOURCE, trigger_ref=fp).exclude(
        state__in=[s.value if hasattr(s, "value") else s for s in models.TS_TERMINAL_CASE_STATES]).first()


def maintenance_reason(devices: list[str]) -> str:
    from ..execution import eligibility

    try:
        conflicts = eligibility._maintenance_conflicts(devices)        # pylint: disable=protected-access
    except Exception:  # noqa: BLE001 - unreadable maintenance state: do not suppress (fail toward a human-visible case)
        return ""
    return "; ".join(f"{d}: {r}" for d, r in sorted(conflicts.items()))


def admission(incident: Incident, cfg: IntakeConfig, now: datetime, *, maintenance: Callable[[list[str]], str] | None = None) -> tuple[bool, str]:
    """Dedup / maintenance / loop / budget gates.  Durable: decided from the case table, so a restart never re-opens a case."""
    if _open_for(incident.fingerprint) is not None:
        return False, "OPEN_CASE_EXISTS"
    if maintenance is not None:
        why = maintenance(incident.devices)
        if why:
            return False, f"MAINTENANCE_ACTIVE ({why})"[:200]
    last = models.TsCase.objects.filter(trigger_source=TRIGGER_SOURCE, trigger_ref=incident.fingerprint).order_by("-opened_at").first()
    if last is not None and (now - last.opened_at).total_seconds() < cfg.cooldown_seconds:
        return False, "COOLDOWN_ACTIVE"
    live = models.TsCase.objects.filter(trigger_source=TRIGGER_SOURCE, opened_at__gte=now - timedelta(hours=1)).exclude(trigger_ref__startswith="REPLAY")
    if live.count() >= cfg.max_cases_per_hour:                              # controlled replays never consume the live budget
        return False, "HOURLY_CASE_BUDGET_EXHAUSTED"
    return True, ""


IDLE_AFTER_SECONDS = 600


def idle_reason(fp: str, now: datetime) -> str:
    """The fault is still present but its open case has made no progress for IDLE_AFTER_SECONDS (e.g. diagnosed without a
    proposal): never a duplicate case, but a human is told once instead of the intake staying silently blocked."""
    case = _open_for(fp)
    if case is None:
        return ""
    last = models.TsAuditEvent.objects.filter(case=case).order_by("-occurred_at").values_list("occurred_at", flat=True).first()
    if last is not None and (now - last).total_seconds() >= IDLE_AFTER_SECONDS:
        return f"OPEN_CASE_IDLE {case.case_id} ({case.state})"
    return ""


def start_dispatch(handoff_id: str) -> bool:
    """Start the existing sandboxed dispatcher unit for this handoff (polkit allows exactly this unit pattern, verb start)."""
    if not HANDOFF_ID.fullmatch(handoff_id):
        return False
    rc = subprocess.run(["systemctl", "start", "--no-block", f"nmas-troubleshooter-dispatch@{handoff_id}.service"],
                        capture_output=True, text=True, timeout=30, check=False).returncode
    return rc == 0


def dispatch_active(handoff_id: str) -> bool:
    """True while the handoff's dispatcher unit is running (or starting); failures read as not running."""
    if not HANDOFF_ID.fullmatch(handoff_id):
        return False
    try:
        out = subprocess.run(["systemctl", "is-active", f"nmas-troubleshooter-dispatch@{handoff_id}.service"],
                             capture_output=True, text=True, timeout=15, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return True                                  # unknown: never start a second dispatcher on a guess
    return out in ("active", "activating", "reloading")


def fingerprint_ends(fp: str, prefix: str = "") -> list[tuple[str, str]]:
    """``LINK:a:ifa|b:ifb`` / ``IFACE:dev:if`` (optionally prefixed) -> [(device, interface), ...]; anything else -> []."""
    body = fp[len(prefix):] if prefix and fp.startswith(prefix) else fp
    kind, _, rest = body.partition(":")
    if kind == "LINK":
        parts = [tuple(x.split(":", 1)) for x in rest.split("|")]
    elif kind == "IFACE":
        parts = [tuple(rest.split(":", 1))]
    else:
        return []
    return [p for p in parts if len(p) == 2 and all(p)]


def read_config_admin(device: str, interface: str, cfg: IntakeConfig) -> str | None:
    """Administrative state from the running configuration (``shutdown`` present -> down).  Read-only; None if unreadable."""
    if not re.fullmatch(r"Ethernet[0-9/]{1,8}", interface):
        return None
    argv = ["docker", "exec", f"{cfg.container_prefix}{device}", "Cli", "-p", "15", "-c", f"show running-config interfaces {interface}"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = [line.strip() for line in out.stdout.splitlines()]
    if out.returncode != 0 or f"interface {interface}" not in lines:
        return None
    return "down" if "shutdown" in lines else "up"


def _policy_lookup(op: dict) -> dict | None:
    from . import recovery

    try:
        raw = recovery.policy_for(op, recovery.load_policies())
    except Exception:  # noqa: BLE001 - an unreadable policy file authorizes nothing
        return None
    return raw if raw is not None and recovery.policy_active(raw) else None


def _protected_flows() -> list[dict]:
    """Protected flows for clearance verification: settings, else those named by the standing policies (read-only pings)."""
    raw = getattr(settings, "NMAS_TS_PROTECTED_FLOWS", None)
    if raw:
        try:
            return list(json.loads(raw) if isinstance(raw, str) else raw)
        except ValueError:
            return []
    from . import recovery

    try:
        policies = recovery.load_policies()
    except Exception:  # noqa: BLE001
        return []
    seen, out = set(), []
    for p in policies.values():
        for f in p.get("protected_flows") or []:
            if f.get("name") not in seen:
                seen.add(f.get("name"))
                out.append(f)
    return out


def _measure_flows(flows: list[dict]) -> dict:
    from . import recovery

    return recovery.measure_flows(flows)


@dataclass
class IntakeDeps:
    run_case: Callable[..., Any] | None = None
    open_handoff: Callable[..., Any] | None = None
    dispatch: Callable[[str], bool] = start_dispatch
    notify: Callable[[str, str], Any] = notify.send
    policy_lookup: Callable[[dict], dict | None] = _policy_lookup
    maintenance: Callable[[list[str]], str] | None = maintenance_reason
    flows: Callable[[], list[dict]] = _protected_flows
    measure: Callable[[list[dict]], dict] = _measure_flows
    dispatch_active: Callable[[str], bool] = dispatch_active
    topology_paths: bool = False                 # production intake: True (record_topology_paths reads the live topology)
    topology_cfg: Any = None


def _store_incident_evidence(actor, case, incident: Incident, now: datetime) -> list[str]:
    """Persist the structured observations, classification and decision on the case (no model needed to read them)."""
    ids: list[str] = []
    if incident.route_evidence is not None:
        route_doc = incident.route_evidence
        ev = repo.store_evidence(
            actor, case, source_type="route_intent", device=incident.devices[0],
            command_or_api="authorized read-only RIB collection",
            adapter="nmas-intake", parser="route_intent.evaluate", parser_version="1",
            collected_at=route_doc["observed_at"], raw=json.dumps(route_doc, sort_keys=True, default=str),
        )
        ids.append(ev.evidence_id)
        scope = (incident.classification.scope if incident.classification else {})
        repo.record_observation(
            actor, case, key=f"intake.route_intent@{scope.get('target_id', '-')}",
            target=incident.devices[0], observed_at=route_doc["observed_at"],
            value={"intent_revision": route_doc["intent_revision"],
                   "topology_revision": route_doc["topology_revision"],
                   "classification": route_doc["classification"],
                   "gateway_evidence": route_doc.get("gateway_evidence", []),
                   "service_telemetry": route_doc.get("service_telemetry", {}),
                   "collector": route_doc["collector"]},
            source="nmas-intake", evidence=ev,
            max_age_seconds=route_doc["max_age_seconds"], parser_version="1",
            dedupe_key=(f"route-intent:{route_doc['intent_revision']}:{scope.get('target_id', '-')}:"
                        f"{incident.devices[0]}:{int(route_doc['observed_at'].timestamp())}"),
        )
        telemetry = route_doc.get("service_telemetry") or {}
        service_devices = route_doc.get("service_devices") or []
        if telemetry and len(service_devices) >= 2:
            failed = sorted(name for name, ok in telemetry.items() if ok is False)
            repo.record(
                actor, case, "correlation", basis="DERIVED", evidence_ids=[ev.evidence_id],
                stage_decision="automatic route-intent/service-telemetry correlation",
                alert_ids=[incident.fingerprint], common_fault_candidate=f"{incident.devices[0]} intended route missing",
                topology_edge={"from": service_devices[0], "to": service_devices[1],
                               "af": scope.get("af", "")}, role="CAUSE", confidence=0.99,
                rules=["C1 gateway-measured flow crosses the declared service edge",
                       "C2 failed address family matches the missing intended route",
                       "C3 unaffected measured address families/directions remain explicit"],
                metrics={"devices": service_devices, "gateway_probe": telemetry, "failed_probes": failed},
                conclusion=(f"Measured failures {failed} correlate with {scope.get('target_id', '-')}; "
                            "all measured outcomes are retained, including healthy controls."),
            )
    for s in incident.samples or incident.members:
        if s.device not in repo._case_devices(case):                  # pylint: disable=protected-access
            continue
        ev = repo.store_evidence(actor, case, source_type="device_state", device=s.device, command_or_api="show interfaces | json",
                                 adapter="nmas-intake", parser="faults.interface_samples", parser_version="1",
                                 collected_at=s.at, raw=json.dumps(s.as_dict(), sort_keys=True))
        ids.append(ev.evidence_id)
        repo.record_observation(actor, case, key=f"{faults.EVIDENCE_KEY}@{s.interface}", target=s.device, observed_at=s.at,
                                value={"admin": s.admin, "oper": s.oper, "link_status": s.link_status, "protocol": s.protocol,
                                       "link_status_changes": s.link_status_changes, "last_change": faults._iso(s.last_change)},  # pylint: disable=protected-access
                                source="nmas-intake", evidence=ev, max_age_seconds=300, parser_version="1",
                                dedupe_key=f"intake:{s.device}:{s.interface}:{int(s.at.timestamp())}")
    cl = incident.classification
    if cl is not None:
        doc = {"classification": cl.as_dict(), "decision": incident.decision, "secondary": incident.secondary}
        ev = repo.store_evidence(actor, case, source_type="deterministic_classification", device=incident.devices[0],
                                 command_or_api="faults.classify_link", adapter="nmas-intake", parser="faults", parser_version="1",
                                 collected_at=now, raw=json.dumps(doc, sort_keys=True, default=str))
        ids.append(ev.evidence_id)
    return ids


def record_decision(actor, case, decision: dict, *, evidence_ids: list[str], now: datetime, stage: str = "intake") -> None:
    repo.audit(actor, case, "REMEDIATION_DECISION", decision=f"{decision['outcome']} {decision['category']}"[:255],
               result=decision["outcome"], risk="", operation=json.dumps(decision.get("operation") or {}, sort_keys=True)[:255],
               rationale=json.dumps({"stage": stage, "rationale": decision.get("rationale", ""), "denied": decision.get("denied", []),
                                     "policy_id": decision.get("policy_id", ""), "cause_status": decision.get("cause_status")})[:3000],
               evidence_ids=evidence_ids, now=now)


def open_incident(incident: Incident, deps: IntakeDeps | None = None, *, now: datetime | None = None) -> dict:
    """Open the case, persist deterministic evidence + decision, run the deterministic Troubleshooter, delegate to Codex and
    start the dispatcher.  No device write."""
    from core import troubleshooting_views as tv

    from . import ai
    from . import runtime as rt

    deps = deps or IntakeDeps()
    now = now or datetime.now(timezone.utc)
    if incident.classification is not None and incident.decision is None:
        incident.decision = faults.decide(incident.classification, policy_lookup=deps.policy_lookup)
    actor = repo.Actor(ACTOR_NAME, "system", tenant="default", devices=frozenset(incident.devices))
    title_kind = {faults.ADMIN_STATE_MISMATCH: "interface intent violation", faults.OPERATIONAL_LINK_DOWN: "operational link down",
                  faults.LINK_FLAPPING: "link flapping", faults.INTERFACE_DEGRADATION: "interface degradation",
                  faults.ROUTING_ADJACENCY_FAILURE: "routing adjacency failure"}.get(incident.category, incident.category)
    is_route_intent = incident.route_evidence is not None
    case = repo.open_case(
        actor, trigger_source=TRIGGER_SOURCE, trigger_ref=incident.fingerprint, severity="HIGH",
        idempotency_key=f"intake:{incident.fingerprint}:{int(incident.onset.timestamp())}",
        title=f"Monitoring: {', '.join(incident.devices)} {title_kind}", symptom=incident.symptom(),
        service_intent={"service": "versioned per-prefix routing intent" if is_route_intent else "managed-device interface intent",
                        "source": (f"route-intent:{incident.route_evidence['intent_revision']}" if is_route_intent else "nmas-intake"),
                        "fault_category": incident.category},
        affected_scope={"devices": incident.devices,
                        "interfaces": [f"{s.device}:{s.interface}" for s in (incident.samples or incident.members)],
                        **({"route": incident.classification.scope} if is_route_intent and incident.classification else {})},
        target_states={d: "UNKNOWN" for d in incident.devices}, runbook="RB02", first_detected_at=incident.onset, now=now)
    evidence_ids: list[str] = []
    try:
        evidence_ids = _store_incident_evidence(actor, case, incident, now)
        if incident.decision is not None:
            record_decision(actor, case, incident.decision, evidence_ids=evidence_ids, now=now)
        if deps.topology_paths:
            try:
                record_topology_paths(actor, case, incident, deps.topology_cfg or IntakeConfig(), now)
            except Exception as exc:  # noqa: BLE001 - path evidence is additive; its absence is audited, never fatal
                repo.audit(actor, case, "TOPOLOGY_PATHS_ERROR", decision=f"{type(exc).__name__}: {exc}"[:255], result="ERROR", now=now)
            for line in incident.secondary:
                repo.audit(actor, case, "SECONDARY_SYMPTOM", decision=line[:255], result="CORRELATED", now=now)
    except Exception as exc:  # noqa: BLE001 - evidence persistence never blocks the case; the failure is audited
        repo.audit(actor, case, "INTAKE_EVIDENCE_ERROR", decision=f"{type(exc).__name__}: {exc}"[:255], result="ERROR", now=now)
    decision = incident.decision or {}
    if decision.get("outcome") in (faults.DIAGNOSE_AND_ESCALATE, faults.PROPOSE_FOR_APPROVAL, faults.INSUFFICIENT_EVIDENCE):
        deps.notify(f"[NMAS] {case.case_id}: {incident.category} on {', '.join(incident.devices)} - {decision['outcome']}",
                    f"{incident.symptom()}\n\nDeterministic remediation decision: {decision['outcome']}\n"
                    f"Automatic remediation denied because:\n  - " + "\n  - ".join(decision.get("denied") or ["-"]) +
                    f"\n\nEvidence: {', '.join(evidence_ids) or '-'}\nThe case stays open for investigation; Codex diagnosis follows "
                    "if the AI path is available. No configuration change will be made automatically.\n")
    (deps.run_case or rt.run_case)(actor, case.case_id, tv._runtime_deps())
    case = models.TsCase.objects.get(pk=case.pk)
    cl = incident.classification
    pre = ""
    if cl is not None:
        pre = (f" Deterministic pre-classification by NMAS (no model involved): {cl.category}; condition "
               f"{'confirmed' if cl.condition_confirmed else 'not confirmed'}; cause {cl.cause_status}. {cl.summary}."
               + (f" Possible causes (NOT asserted): {'; '.join(cl.possible_causes[:5])}." if cl.possible_causes else "")
               + (f" Correlated secondary symptoms: {'; '.join(incident.secondary)[:400]}." if incident.secondary else "")
               + f" Stored evidence: {', '.join(evidence_ids)}. Deterministic remediation decision: {decision.get('outcome', '-')}."
               " Verify this classification against live evidence; distinguish administrative DOWN, operational DOWN with "
               "admin UP, repeated transitions, degradation, routing and reachability failures. An administrative-enable correction "
               "can only help an interface that is administratively down; for an operational, physical, flapping or routing fault with "
               "no registered safe correction, do not invent a change: submit an evidence-backed escalation.")
    handoff = (deps.open_handoff or ai.open_handoff)(
        actor, case, agent_identity="",
        uncertainty=(f"Monitoring alarm on managed device(s) {', '.join(incident.devices)}: {incident.symptom()} End-host configuration is "
                     "out of scope. Collect live evidence on the affected target(s) with request_diagnostic_test for the applicable catalogue "
                     "tests, then determine the cause on the managed device(s). If a causal fault is evidenced and a registered corrective "
                     "operation applies, call propose_remediation with the exact minimal operation, the causal evidence ids and a "
                     "rollback plan BEFORE submit_investigation_result; then submit the result." + pre)[:7000],
        special_case_reason=f"monitoring-triggered incident {incident.fingerprint}: unattended diagnosis requested by NMAS intake")
    started = deps.dispatch(handoff.record_id)
    repo.audit(actor, case, "INTAKE_DISPATCH", decision=f"{handoff.record_id} started={started}", result="OK" if started else "NOT_STARTED",
               rationale=f"fingerprint {incident.fingerprint}")                     # actual dispatch time, not the poll's
    if not started:
        deps.notify(f"[NMAS] Intake could not start Codex dispatch for {case.case_id}",
                    f"Handoff {handoff.record_id} is open but the dispatcher unit did not start; the deterministic classification "
                    f"({incident.category}) and evidence are preserved and the intake retries every {DISPATCH_RETRY_SECONDS}s.\n")
    return {"case": case.case_id, "handoff": handoff.record_id, "dispatch_started": started, "fingerprint": incident.fingerprint,
            "category": incident.category, "decision": decision.get("outcome")}


# ------------------------------------------------------------------------------------------------------------------ the loop
@dataclass
class Intake:
    cfg: IntakeConfig = field(default_factory=IntakeConfig.from_settings)
    reader: Callable[[str, IntakeConfig], list | None] = read_device
    intent: Callable[[str], dict | None] = hc._intended_admin_states
    deps: IntakeDeps = field(default_factory=IntakeDeps)
    first_seen: dict[tuple[str, str], datetime] = field(default_factory=dict)
    suppressed: set[tuple[str, str]] = field(default_factory=set)
    _peers: dict | None = None
    adjacency_reader: Callable[[str, IntakeConfig], list | None] = read_adjacencies
    config_admin: Callable[[str, str, IntakeConfig], str | None] | None = None   # production: read_config_admin
    history: dict[tuple[str, str], faults.LinkHistory] = field(default_factory=dict)
    adj_expected: dict[tuple, faults.AdjacencySample] = field(default_factory=dict)
    adj_first_missing: dict[tuple, datetime] = field(default_factory=dict)
    link_incident_at: dict[str, tuple[datetime, str]] = field(default_factory=dict)   # device -> (last abnormal time, fingerprint)
    route_reader: Callable[[str, IntakeConfig], dict | None] | None = read_route_sources
    route_intent_reader: Callable[[route_intent.RouteIntent, IntakeConfig], dict | None] | None = read_route_intent_ribs
    freshness_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    rsrc_baseline: dict[tuple[str, str], dict[str, int]] = field(default_factory=dict)   # (device, af) -> learned healthy counts
    rsrc_first_bad: dict[tuple[str, str, str], datetime] = field(default_factory=dict)
    route_intent_first_bad: dict[tuple[str, str, str], datetime] = field(default_factory=dict)
    _route_intent_pass_id: str = field(default="", init=False, repr=False)           # correlation id of the current pass
    _route_intent_detail: dict | None = field(default=None, init=False, repr=False)
    adj_incident_at: dict[str, tuple[datetime, str]] = field(default_factory=dict)
    cleared_since: dict[str, datetime] = field(default_factory=dict)
    dispatch_attempts: dict[str, tuple[datetime, int]] = field(default_factory=dict)
    passes: int = 0
    last_classes: dict = field(default_factory=dict)

    # ------------------------------------------------------------------------------------------------ interface incidents
    def _interface_incidents(self, now: datetime) -> tuple[list[Incident], dict, set[str]]:
        samples: dict[tuple[str, str], faults.InterfaceSample] = {}
        unread: set[str] = set()
        for device in self.cfg.devices:
            rows = self.reader(device, self.cfg)
            if rows is None:
                unread.add(device)            # unreadable is NOT healthy: keep its pending state, decide nothing new
                continue
            for row in rows:
                s = _as_sample(row, now)
                if s.interface.startswith("Management"):
                    continue
                if s.admin == "down" and self.config_admin is not None:
                    configured = self.config_admin(s.device, s.interface, self.cfg)
                    if configured == "up":          # status says disabled but no shutdown is configured: NOT an admin shutdown
                        s = dataclasses.replace(s, admin="up", source=s.source + "; admin from running-config (no shutdown configured)")
                samples[(s.device, s.interface)] = s
                self.history.setdefault((s.device, s.interface), faults.LinkHistory()).update(s)
        intents: dict[str, dict] = {}
        classes: dict[tuple[str, str], faults.Classification] = {}
        abnormal: dict[tuple[str, str], faults.InterfaceSample] = {}
        for key, s in samples.items():
            want = intents.setdefault(s.device, self.intent(s.device) or {})
            cl = faults.classify_interface(s, want.get(s.interface), self.history.get(key), now=now, confirm_seconds=self.cfg.confirm_seconds)
            classes[key] = cl
            bad_state = want.get(s.interface) == "up" and (s.admin != "up" or s.oper != "up")
            if bad_state or cl.category in INCIDENT_CATEGORIES:
                abnormal[key] = s
        for key in list(self.first_seen):
            if key not in abnormal and key[0] not in unread:
                self.first_seen.pop(key)                                     # cleared before confirmation: not (yet) an incident
        for key in abnormal:
            self.first_seen.setdefault(key, now)
        confirmed = {}
        for key, s in abnormal.items():
            cat = classes[key].category
            if cat in (faults.LINK_FLAPPING, faults.INTERFACE_DEGRADATION, faults.OPERATIONAL_LINK_DOWN):
                confirmed[key] = s                                           # debounced inside the classifier
            elif (now - self.first_seen[key]).total_seconds() >= self.cfg.confirm_seconds:
                confirmed[key] = s
        # an end confirmed abnormal pulls in its peer's classification (context: e.g. the admin-disabled far end)
        for key in list(confirmed):
            peer = (self._peers or {}).get(key)
            if peer in abnormal and peer not in confirmed and classes[peer].category == faults.ADMIN_STATE_MISMATCH:
                confirmed[peer] = abnormal[peer]
        self.last_classes = classes
        incidents = correlate(confirmed, self._peers or {}, self.first_seen, classes=classes, samples=samples)
        for inc in incidents:
            for s in inc.samples or inc.members:
                self.link_incident_at[s.device] = (now, inc.fingerprint)
        return incidents, samples, unread

    # ------------------------------------------------------------------------------------------------ routing incidents
    def _adjacency_incidents(self, now: datetime) -> list[Incident]:
        if not self.cfg.routing_devices or self.passes % max(1, self.cfg.routing_every):
            return []
        out = []
        for device in self.cfg.routing_devices:
            rows = self.adjacency_reader(device, self.cfg)
            if rows is None:
                continue                                          # unreadable: decide nothing for this device
            observed = {r.key: r for r in rows}
            for r in rows:                                        # learned baseline: healthy adjacencies seen by this process
                if r.healthy and r.key not in self.adj_expected:
                    self.adj_expected[r.key] = r
            expected = [e for k, e in self.adj_expected.items() if k[0] == device]
            recent = self.link_incident_at.get(device)
            related = {device: recent[1]} if recent and (now - recent[0]).total_seconds() <= ADJ_SECONDARY_GRACE_S else {}
            failed = faults.classify_adjacency(expected, rows, now=now, expectation_source="LEARNED_BASELINE (adjacencies observed healthy "
                                               "by this intake process; not authoritative intent)", link_incidents=related)
            failed_keys = set()
            for cl in failed:
                key = (device, cl.scope["protocol"], cl.scope["neighbor"])
                failed_keys.add(key)
                first = self.adj_first_missing.setdefault(key, now)
                if (now - first).total_seconds() < self.cfg.confirm_seconds:
                    continue
                fp = f"ADJ:{device}:{cl.scope['protocol']}:{cl.scope['neighbor']}"
                self.adj_incident_at[device] = (now, fp)           # unprefixed, like link_incident_at (_attach_secondary prefixes)
                inc = Incident(fp, [device], [], first, classification=cl)
                if related:
                    inc.secondary = [f"possibly secondary to {related[device]}"]
                out.append(inc)
            for key in list(self.adj_first_missing):
                if key[0] == device and key not in failed_keys and key in observed:
                    self.adj_first_missing.pop(key)
        return out

    def _route_incidents(self, now: datetime) -> list[Incident]:
        """Learned-baseline route-source collapse (RIP / OSPF / OSPF externals / OSPFv3 / IS-IS / BGP, both families)."""
        if self.route_reader is None or not self.cfg.routing_devices or self.passes % max(1, self.cfg.routing_every):
            return []
        out = []
        for device in self.cfg.routing_devices:
            fams = self.route_reader(device, self.cfg)
            if fams is None:
                continue                                          # unreadable: decide nothing for this device
            related = {}
            for src in (self.link_incident_at.get(device), self.adj_incident_at.get(device)):
                if src and (now - src[0]).total_seconds() <= ADJ_SECONDARY_GRACE_S:
                    related = {"fingerprint": src[1]}
            for af, counts in fams.items():
                if counts is None:
                    continue
                base = self.rsrc_baseline.get((device, af))
                if base is None:
                    self.rsrc_baseline[(device, af)] = dict(counts)
                    continue
                failed = routing.classify_source_counts(device, af, base, counts, now=now, expectation_source=(
                    "LEARNED_BASELINE (route-source counts observed healthy by this intake process; not authoritative intent)"))
                bad = {cl.scope["source"]: cl for cl in failed if cl.category == faults.ROUTE_OR_REACHABILITY_FAILURE}
                for key in [k for k in self.rsrc_first_bad if k[:2] == (device, af) and k[2] not in bad]:
                    self.rsrc_first_bad.pop(key)                  # recovered (>= half again)
                if not bad:
                    # learn upward only while healthy: a slow drift below the baseline never silently lowers the bar
                    self.rsrc_baseline[(device, af)] = {k: max(int(counts.get(k, 0)), int(base.get(k, 0))) for k in {*base, *counts}}
                    continue
                for src, cl in bad.items():
                    first = self.rsrc_first_bad.setdefault((device, af, src), now)
                    if (now - first).total_seconds() < self.cfg.confirm_seconds:
                        continue
                    if related:
                        cl.evidence["possibly_secondary_to"] = related["fingerprint"]
                    inc = Incident(f"RSRC:{device}:{af}:{src}", [device], [], first, classification=cl)
                    if related:
                        inc.secondary = [f"possibly secondary to {related['fingerprint']}"]
                    out.append(inc)
        return out

    def _intent_route_incidents(self, now: datetime) -> tuple[list[Incident], list[dict]]:
        """Run one route-intent pass and return its incidents plus one structured ``route_intent_pass`` record.

        A pass never stops monitoring: an unexpected failure becomes ``ERROR`` / ``ROUTE_INTENT_PASS_EXCEPTION`` (exception
        type only, no message, so no device output can leak) and the remaining intake work for this poll continues.
        """
        if not self.cfg.route_intent_path or self.passes % max(1, self.cfg.routing_every):
            return [], []
        self._route_intent_pass_id = f"RIP-{secrets.token_hex(6)}"
        self._route_intent_detail = None
        try:
            incidents, status = self._intent_route_pass(now)
        except Exception as exc:  # noqa: BLE001 - one failed pass never stops the intake
            log.error("route intent pass %s failed: %s", self._route_intent_pass_id, type(exc).__name__)
            incidents, status = [], [{"route_intent": "ERROR", "reason": "ROUTE_INTENT_PASS_EXCEPTION",
                                      "exception": type(exc).__name__}]
        detail = self._route_intent_detail or {}
        confirmed = frozenset(i.fingerprint for i in incidents)
        records = [route_intent_pass_record(row, pass_id=self._route_intent_pass_id, at=now, results=detail.get("results"),
                                            expectations=detail.get("expectations", 0), confirmed=confirmed)
                   for row in status]
        return incidents, records

    def _intent_route_pass(self, now: datetime) -> tuple[list[Incident], list[dict]]:
        """Evaluate reviewed per-prefix intent against one fresh, independently revision-pinned RIB snapshot."""
        try:
            intent = route_intent.load(self.cfg.route_intent_path)
        except route_intent.IntentError as exc:
            return [], [{"route_intent": "REFUSED", "reason": f"INTENT_INVALID: {exc}"}]
        if not self.cfg.topology_revision:
            return [], [{"route_intent": "REFUSED", "reason": "TOPOLOGY_REVISION_UNBOUND",
                         "intent_revision": intent.revision}]
        if self.cfg.topology_revision != intent.topology_revision:
            return [], [{"route_intent": "REFUSED", "reason": "TOPOLOGY_REVISION_MISMATCH",
                         "intent_revision": intent.revision, "expected": intent.topology_revision,
                         "observed": self.cfg.topology_revision}]
        if self.route_intent_reader is None:
            return [], [{"route_intent": "REFUSED", "reason": "RIB_READER_UNBOUND",
                         "intent_revision": intent.revision}]
        snapshot = self.route_intent_reader(intent, self.cfg)
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("ribs"), dict):
            return [], [{"route_intent": "INDETERMINATE", "reason": "RIB_SNAPSHOT_UNREADABLE",
                         "intent_revision": intent.revision}]
        try:
            observed_at = datetime.fromisoformat(str(snapshot["observed_at"]).replace("Z", "+00:00"))
            freshness_now = self.freshness_clock()
            age = (freshness_now - observed_at).total_seconds()
        except (KeyError, TypeError, ValueError):
            return [], [{"route_intent": "INDETERMINATE", "reason": "RIB_TIMESTAMP_INVALID",
                         "intent_revision": intent.revision}]
        if observed_at.tzinfo is None or age < 0 or age > self.cfg.route_intent_max_age_seconds:
            return [], [{"route_intent": "INDETERMINATE", "reason": "RIB_SNAPSHOT_STALE_OR_FUTURE",
                         "intent_revision": intent.revision, "age_seconds": round(age, 1)}]
        device_times = snapshot.get("device_observed_at") or {}
        stale_devices = []
        for device in sorted({item.device for item in intent.expectations}):
            try:
                stamp = datetime.fromisoformat(str(device_times[device]).replace("Z", "+00:00"))
                device_age = (freshness_now - stamp).total_seconds()
                if stamp.tzinfo is None or device_age < 0 or device_age > self.cfg.route_intent_max_age_seconds:
                    stale_devices.append(device)
            except (KeyError, TypeError, ValueError):
                stale_devices.append(device)
        if stale_devices:
            return [], [{"route_intent": "INDETERMINATE", "reason": "RIB_DEVICE_TIMESTAMPS_MISSING_OR_STALE",
                         "intent_revision": intent.revision, "devices": stale_devices}]
        results = route_intent.evaluate(intent, snapshot["ribs"], now=observed_at)
        self._route_intent_detail = {"results": results, "expectations": len(intent.expectations)}
        incidents, inconclusive = [], 0
        active = set()
        for classification in results:
            scope = classification.scope
            key = (scope["target_id"], scope["device"], classification.evidence["route_prefix"])
            if classification.category == faults.INDETERMINATE:
                inconclusive += 1
                continue
            if classification.category == faults.NO_FAULT:
                self.route_intent_first_bad.pop(key, None)
                continue
            active.add(key)
            first = self.route_intent_first_bad.setdefault(key, now)
            if (now - first).total_seconds() < self.cfg.confirm_seconds:
                continue
            fp = f"RINT:{intent.revision}:{scope['target_id']}:{scope['device']}"
            route_doc = {
                "schema": "nmas.troubleshooting.route-intent-observation/1",
                "pass_id": getattr(self, "_route_intent_pass_id", ""),
                "intent_revision": intent.revision, "topology_revision": intent.topology_revision,
                "observed_at": observed_at, "age_seconds": round(age, 1),
                "max_age_seconds": self.cfg.route_intent_max_age_seconds,
                "collector": str(snapshot.get("collector") or "nmas-intake read-only RIB"),
                "gateway_evidence": sorted({int(seq) for seq in snapshot.get("gateway_evidence", [])
                                             if isinstance(seq, int) and not isinstance(seq, bool)}),
                "service_telemetry": {str(name)[:64]: value for name, value in
                                      (snapshot.get("service_telemetry") or {}).items()
                                      if isinstance(name, str) and isinstance(value, bool)},
                "service_devices": sorted({str(device)[:64] for device in (snapshot.get("service_devices") or [])
                                           if isinstance(device, str) and device})[:8],
                "device_observed_at": (snapshot.get("device_observed_at") or {}).get(scope["device"]),
                "classification": classification.as_dict(),
            }
            incidents.append(Incident(fp, [scope["device"]], [], first, classification=classification,
                                      route_evidence=route_doc))
        for key in list(self.route_intent_first_bad):
            if key not in active and not any(r.scope.get("target_id") == key[0] and r.scope.get("device") == key[1]
                                             and r.category == faults.INDETERMINATE for r in results):
                self.route_intent_first_bad.pop(key)
        state = "DEGRADED" if active else ("INDETERMINATE" if inconclusive else "HEALTHY")
        status = {"route_intent": state, "intent_revision": intent.revision,
                  "topology_revision": intent.topology_revision, "evaluated": len(results),
                  "faults": len(active), "inconclusive": inconclusive, "age_seconds": round(age, 1)}
        return incidents, [status]

    def _attach_secondary(self, inc: Incident, now: datetime) -> dict | None:
        """An adjacency loss explained by a concurrent link incident is appended to that incident's open case (no new case)."""
        related = inc.classification.evidence.get("possibly_secondary_to") if inc.classification else None
        if not related:
            return None
        case = _open_for(self.cfg.fingerprint_prefix + related)
        line = f"{inc.classification.summary} (possibly secondary to {related})"
        if case is not None:
            already = models.TsAuditEvent.objects.filter(case=case, action="SECONDARY_SYMPTOM", decision=line[:255]).exists()
            if not already:
                actor = repo.Actor(ACTOR_NAME, "system", tenant=case.tenant, devices=frozenset(repo._case_devices(case)))  # pylint: disable=protected-access
                repo.audit(actor, case, "SECONDARY_SYMPTOM", decision=line[:255], result="CORRELATED",
                           rationale=json.dumps(inc.classification.as_dict(), default=str)[:3000], now=now)
            return {"fingerprint": inc.fingerprint, "secondary_to": case.case_id}
        return {"fingerprint": inc.fingerprint, "skipped": f"SECONDARY_TO_LINK_INCIDENT {related}"}

    # ------------------------------------------------------------------------------------------------ the pass
    def poll(self, now: datetime | None = None) -> list[dict]:
        now = now or datetime.now(timezone.utc)
        if self._peers is None:
            self._peers = peers(set(self.cfg.devices))
        incidents, samples, unread = self._interface_incidents(now)
        adj = self._adjacency_incidents(now)
        adj += self._route_incidents(now)
        intent_incidents, intent_status = self._intent_route_incidents(now)
        adj += intent_incidents
        self.passes += 1
        results = intent_status
        for inc in adj:
            attached = self._attach_secondary(inc, now)
            if attached is not None:
                results.append(attached)
            else:
                incidents.append(inc)
        for incident in incidents:
            incident.fingerprint = self.cfg.fingerprint_prefix + incident.fingerprint
            if incident.classification is not None:
                incident.decision = faults.decide(incident.classification, policy_lookup=self.deps.policy_lookup)
            ok, why = admission(incident, self.cfg, now, maintenance=self.deps.maintenance)
            if not ok and why == "OPEN_CASE_EXISTS":
                why = idle_reason(incident.fingerprint, now) or why
            if not ok:
                if why != "OPEN_CASE_EXISTS" and (incident.fingerprint, why) not in self.suppressed:
                    self.suppressed.add((incident.fingerprint, why))
                    log.warning("intake suppressed %s: %s", incident.fingerprint, why)
                    self.deps.notify(f"[NMAS] Incident {incident.fingerprint} not auto-opened: {why}",
                                     f"{incident.symptom()}\nAutomatic intake declined ({why}); a human must review.\n")
                results.append({"fingerprint": incident.fingerprint, "skipped": why,
                                **({"category": incident.category} if incident.classification else {})})
                continue
            try:
                opened = open_incident(incident, self.deps, now=now)
                results.append(opened)
                if incident.route_evidence is not None:
                    results.append(route_intent_case_record(incident, opened, now))
            except Exception as exc:  # noqa: BLE001 - one failed intake never stops monitoring
                results.append({"fingerprint": incident.fingerprint, "error": f"{type(exc).__name__}: {exc}"[:300]})
                if incident.route_evidence is not None:
                    results.append(route_intent_case_record(incident, None, now, error=type(exc).__name__))
        live = {i.fingerprint for i in incidents}
        self.suppressed = {s for s in self.suppressed if s[0] in live}
        results += self._retry_dispatch(now)
        if self.cfg.verify_clear:
            results += self._close_cleared(samples, unread, live, now)
        return results

    # ------------------------------------------------------------------------------------------------ AI-path outage
    def _retry_dispatch(self, now: datetime) -> list[dict]:
        """While the AI path is unavailable the case keeps its deterministic evidence; the dispatcher is (re)started for an OPEN
        handoff whose last start failed, bounded in rate and count.  Starting an already running unit is a no-op."""
        out = []
        cases = models.TsCase.objects.filter(trigger_source=TRIGGER_SOURCE).exclude(state__in=list(models.TS_TERMINAL_CASE_STATES))
        if self.cfg.fingerprint_prefix:
            cases = cases.filter(trigger_ref__startswith=self.cfg.fingerprint_prefix)
        else:
            cases = cases.exclude(trigger_ref__startswith="REPLAY")      # a replay engine owns its own cases
        for case in cases:
            last = models.TsAuditEvent.objects.filter(case=case, action__in=("INTAKE_DISPATCH", "INTAKE_DISPATCH_RETRY")).order_by("-seq").first()
            if last is None:
                continue
            handoff = models.TsAIHandoff.objects.filter(case=case, status="OPEN").first()
            if handoff is None:
                continue
            cp = handoff.checkpoint or {}
            # A unit that STARTED but exited without any progress (e.g. GLOBAL_LEASE_BUSY while another handoff held the single
            # global lease) leaves an OPEN, untouched handoff: treat it like a start failure, once the unit is no longer running.
            stalled = (last.result == "OK" and not cp.get("iteration") and not cp.get("calls")
                       and not (cp.get("model") or {}).get("requests") and not self.deps.dispatch_active(handoff.record_id))
            if last.result != "NOT_STARTED" and not stalled:
                continue
            at, count = self.dispatch_attempts.get(case.case_id, (last.occurred_at, 0))
            if (now - at).total_seconds() < DISPATCH_RETRY_SECONDS or count >= DISPATCH_RETRY_MAX:
                continue
            started = self.deps.dispatch(handoff.record_id)
            self.dispatch_attempts[case.case_id] = (now, count + 1)
            actor = repo.Actor(ACTOR_NAME, "system", tenant=case.tenant, devices=frozenset(repo._case_devices(case)))  # pylint: disable=protected-access
            repo.audit(actor, case, "INTAKE_DISPATCH_RETRY", decision=f"{handoff.record_id} attempt {count + 1} started={started}",
                       result="OK" if started else "NOT_STARTED", now=now,
                       rationale="previous dispatch exited without progress (e.g. GLOBAL_LEASE_BUSY)" if stalled else "previous start failed")
            out.append({"case": case.case_id, "dispatch_retry": count + 1, "started": started})
        return out

    # ------------------------------------------------------------------------------------------------ verified clearance
    def _close_cleared(self, samples: dict, unread: set[str], live: set[str], now: datetime) -> list[dict]:
        """An escalated (non-AUTO) monitoring case whose fault cleared WITHOUT NMAS acting: after the condition has been absent
        for ``confirm_seconds`` (and a flap has stabilised), re-verify every member interface and the protected flows from fresh
        reads, then close ``UNRESOLVED`` with ``cleared_externally`` -- never RESOLVED_VERIFIED, because NMAS did not repair it."""
        out = []
        cases = models.TsCase.objects.filter(trigger_source=TRIGGER_SOURCE).exclude(state__in=list(models.TS_TERMINAL_CASE_STATES))
        if self.cfg.fingerprint_prefix:
            cases = cases.filter(trigger_ref__startswith=self.cfg.fingerprint_prefix)
        else:
            cases = cases.exclude(trigger_ref__startswith="REPLAY")
        for case in cases:
            fp = case.trigger_ref
            if fp in live or not fingerprint_ends(fp, self.cfg.fingerprint_prefix):
                self.cleared_since.pop(fp, None)
                continue
            decision = models.TsAuditEvent.objects.filter(case=case, action="REMEDIATION_DECISION").order_by("seq").first()
            if decision is None or decision.result == faults.AUTO_REMEDIATE:
                continue                                         # policy recovery owns AUTO cases; legacy cases stay with humans
            if models.TsAIHandoff.objects.filter(case=case, status="OPEN").exists():
                continue                                         # never close under a running investigation
            if models.TsRemediationPlan.objects.filter(case=case, status__in=IN_FLIGHT_PLAN_STATES).exists():
                continue
            ends = fingerprint_ends(fp, self.cfg.fingerprint_prefix)
            if not ends or any(e[0] in unread or e not in samples for e in ends):
                continue
            healthy = all(samples[e].admin == "up" and samples[e].oper == "up" for e in ends)
            windows = [self.history[e].window(now) for e in ends if e in self.history]
            stable = all(w["stable_for_s"] is None or w["stable_for_s"] >= faults.FLAP_STABLE_SECONDS for w in windows)
            if not healthy or not stable:
                self.cleared_since.pop(fp, None)
                continue
            since = self.cleared_since.setdefault(fp, now)
            if (now - since).total_seconds() < self.cfg.confirm_seconds:
                continue
            flows = self.deps.flows() or []
            measured = self.deps.measure(flows) if flows else {}
            flows_ok = bool(measured) and all(v.get("loss_pct") == 0.0 for v in measured.values())
            actor = repo.Actor(ACTOR_NAME, "system", tenant=case.tenant, devices=frozenset(repo._case_devices(case)))  # pylint: disable=protected-access
            ids = []
            for e in ends:
                s = samples[e]
                if s.device in repo._case_devices(case):         # pylint: disable=protected-access
                    ev = repo.store_evidence(actor, case, source_type="device_state", device=s.device, command_or_api="show interfaces | json",
                                             adapter="nmas-intake", parser="faults.interface_samples", parser_version="1",
                                             collected_at=s.at, raw=json.dumps(s.as_dict(), sort_keys=True))
                    ids.append(ev.evidence_id)
            disposition = {"outcome": "SAFE_NON_REMEDIATION", "remediation_decision": decision.result,
                           "fault_category": (case.service_intent or {}).get("fault_category", ""),
                           "cleared_externally": True, "nmas_performed_repair": False,
                           "verified_at": faults._iso(now),                 # pylint: disable=protected-access
                           "interfaces": {f"{d}:{i}": {"admin": samples[(d, i)].admin, "oper": samples[(d, i)].oper} for d, i in ends},
                           "protected_flows": {k: {"loss_pct": v.get("loss_pct")} for k, v in measured.items()},
                           "protected_flows_baseline_ok": flows_ok, "evidence_ids": ids}
            repo.audit(actor, case, "FAULT_CLEARED_VERIFIED", decision=f"interfaces up/up and stable; flows {'0% loss' if flows_ok else 'NOT verified'}",
                       result="VERIFIED" if flows_ok else "PARTIAL", rationale=json.dumps(disposition, default=str)[:3000], evidence_ids=ids, now=now)
            try:
                if case.state in ("OPEN", "SCOPING"):                 # legal lifecycle edge only; never forced
                    case = repo.transition_case(actor, case, "COLLECTING", reason="clearance verification evidence collected", now=now)
                repo.close_case(actor, case, "UNRESOLVED", disposition=disposition, now=now)
            except ValueError as exc:
                out.append({"case": case.case_id, "close_error": str(exc)[:200]})
                continue
            self.cleared_since.pop(fp, None)
            self.deps.notify(f"[NMAS] {case.case_id}: fault cleared externally (no NMAS change)",
                             f"Fingerprint {fp} is healthy again and stable; protected flows {'0% loss' if flows_ok else 'not verified'}.\n"
                             f"NMAS made no configuration change ({decision.result}). Closed UNRESOLVED with cleared_externally=true; "
                             "the root cause still needs human follow-up.\n")
            out.append({"case": case.case_id, "closed": "UNRESOLVED", "cleared_externally": True, "flows_ok": flows_ok})
        return out
