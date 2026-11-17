"""Runtime orchestration: authoritative admission -> canonical collectors -> persistence -> Engine -> report (NMAS V2 troubleshooting).

This module composes EXISTING parts only (``collectors``, ``adapters``, ``contracts``, ``repository``, ``baselines.DjangoBaselineSources``,
``engine.Engine``, ``reporting``).  It adds no collector, store or database.

Trust boundaries
* Admission is resolved HERE from the authoritative inventory (``core.services.health.inventory.managed_devices`` by default, plus an optional
  lifecycle provider), never from client-supplied ``target_states``.  The resolved states overwrite ``TsCase.target_states`` (audited) before any probe.
* Collection is read-only (collectors enforce catalogue/allow-lists); unavailable sources become explicit missing-data records, never values.
* Only transports that report gateway provenance can make evidence "live"; the provenance is copied verbatim into the evidence ``scope``.

Canonical mapping (collector s2 observation -> engine observation)
* engine ``target`` = device name; engine ``key`` = ``<canonical key>@<subject>`` (``runbooks.base.join_key``), subject = interface or neighbour.
* ``interface.{admin_state,oper_state,mtu,speed,duplex}`` and ``interface.rate.*`` map 1:1; ``interface.address`` is aggregated per interface;
  ``routing.{ospf,bgp}.neighbor_state`` -> ``routing.neighbor`` ``{state, protocol, vrf, interface, neighbor_id}``;
  syslog ``interface.link_event`` -> per-interface ``{window_s, events[]}``; other syslog -> ``syslog.system_events``;
  ``interface.counter_event`` / rate samples -> ``interface.counter_reset`` ``{reset}``.  Anything else is retained under its own key (not consumed).
* Raw hash / pointer / parser identity / gateway provenance are preserved on the evidence row (``scope``) and the pointer carries the as-received hash.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from core import models as m

from . import baselines as bl
from . import collectors as col
from . import contracts as c
from . import engine as eng
from . import normalization as nz
from . import repository as repo
from . import reporting
from .adapters import capabilities as caps
from .adapters import config_snapshot as cfg_ad
from .adapters import dns as dns_ad
from .adapters import probes as probe_ad
from .adapters import forwarding as fwd_ad
from .adapters import physical as phy_ad
from .adapters import protocol as proto_ad
from .adapters import qos as qos_ad
from .adapters.flow_runtime import FlowRuntimeInput
from .runbooks import REGISTRY
from .runbooks.base import KEY_SEP, join_key

RUNTIME_VERSION = "1.0.0"
RUN_SCHEMA = "nmas.troubleshooting.runtime-run/1"

# Keys the engine obtains from baseline sources, not from device collectors.
BASELINE_KEYS = frozenset({"intent", "golden", "history", "changes", "configs", "slo"})
# Engine key -> CLI catalogue keys (per platform family) that can serve it.  Evidence-only commands have no parser: their observations are
# recorded as PARSER_UNAVAILABLE gaps instead of values.
CANON_TO_CLI: dict[str, dict[str, tuple[str, ...]]] = {
    "interface": {"ceos": ("interfaces",), "iosxe": ("interfaces",), "linux": ("addr",)},
    "routing.neighbor": {"ceos": ("ospf_neighbors", "bgp_summary"), "iosxe": ("ospf_neighbors",), "linux": ("ospf_neighbors", "bgp_summary")},
    "route": {"ceos": ("ip_route", "ipv6_route"), "iosxe": ("ip_route",), "linux": ("route4", "route6")},
    "arp.entry": {"ceos": ("arp", "ipv6_neighbors"), "iosxe": ("arp",), "linux": ("neigh",)},
    "mac.table": {"ceos": ("mac_table",), "iosxe": ("mac_table",), "linux": ()},
    "l2.port": {"ceos": ("switchport",), "iosxe": (), "linux": ()},
    "acl.counters": {"ceos": ("acl_rules", "acl_attach"), "iosxe": (), "linux": ()},
    "stp.port_protection": {"ceos": ("spanning_tree",), "iosxe": (), "linux": ()},
    "stp.state": {"ceos": ("spanning_tree",), "iosxe": ("spanning_tree",), "linux": ()},
}
# Engine keys that a catalogue command fills (used to attach missing-data records to the keys the engine will ask for).
CLI_KEY_CANON = {
    "interfaces": ("interface.oper_state", "interface.admin_state", "interface.mtu"), "addr": ("interface.oper_state", "interface.admin_state", "interface.mtu"),
    "ospf_neighbors": ("routing.neighbor",), "bgp_summary": ("routing.neighbor",), # the RIB / kernel-table commands fill route.rib ONLY: route.fib is an explicit gap (never derived from the RIB)
    "ip_route": ("route.rib",), "route4": ("route.rib",), "ipv6_route": ("route.rib",), "route6": ("route.rib",),
    "running_config": ("config.snapshot",), "frr_config": ("config.snapshot",),
    "arp": ("arp.entry",), "neigh": ("arp.entry",), "ipv6_neighbors": ("arp.entry",), "mac_table": ("mac.table",), "switchport": ("l2.port",),
    "acl_rules": ("acl.counters",), "acl_attach": ("acl.counters",), "spanning_tree": ("stp.state", "stp.port_protection"),
}
DIRECT_KEYS = frozenset({"interface.admin_state", "interface.oper_state", "interface.mtu", "interface.speed", "interface.duplex"})
NEIGHBOR_STATE = {"full": "Full", "two_way": "2-Way", "exstart": "ExStart", "exchange": "Exchange", "loading": "Loading", "init": "Init", "attempt": "Attempt",
                  "down": "Down", "established": "Established", "idle": "Idle", "connect": "Connect", "active": "Active", "opensent": "OpenSent",
                  "openconfirm": "OpenConfirm", "unknown": "Unknown"}
QUALITY = {"OK": "GOOD", "PARTIAL": "PARTIAL", "STALE": "PARTIAL", "UNTRUSTED_PARSE": "UNTRUSTED", "UNKNOWN": "MISSING"}


def _h(*parts, n: int = 16) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:n]


# ------------------------------------------------------------------------------------------------------------------ budgets
@dataclass(frozen=True)
class RuntimeBudget:
    """Bounds for one run.  Requested values are clamped to ``SERVER_CAPS``; they can never exceed them."""

    max_devices: int = 8
    max_seconds: float = 120.0
    max_collection_runs: int = 60      # one extra bounded unit per device when an independent FIB source is injected
    max_commands: int = 16      # one SNMP IF-MIB poll needs ~14 requests; a half table is discarded, so the default must cover a whole poll
    max_bytes: int = 1_000_000
    max_records: int = 5_000
    per_command_timeout_s: float = 20.0

    FIELDS = ("max_devices", "max_seconds", "max_collection_runs", "max_commands", "max_bytes", "max_records", "per_command_timeout_s")

    @classmethod
    def clamp(cls, requested: dict | None = None) -> "RuntimeBudget":
        base = {f: getattr(cls(), f) for f in cls.FIELDS}
        for name, value in (requested or {}).items():
            if name not in base:
                raise ValueError(f"unknown budget field {name!r}")
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"budget {name} must be a positive number")
            base[name] = min(type(base[name])(value), getattr(SERVER_CAPS, name))
        return cls(**base)

    def collector_budget(self) -> col.Budget:
        return col.Budget(max_commands=self.max_commands, max_seconds=min(self.max_seconds, 60.0), max_bytes=self.max_bytes, max_records=self.max_records,
                          per_command_timeout_s=self.per_command_timeout_s)


SERVER_CAPS = RuntimeBudget(max_devices=16, max_seconds=300.0, max_collection_runs=80, max_commands=20, max_bytes=2_000_000, max_records=10_000,
                            per_command_timeout_s=30.0)


# ------------------------------------------------------------------------------------------------------------------ admission
@dataclass(frozen=True)
class DeviceAdmission:
    device: str
    state: str                 # VERIFIED | UNKNOWN (not in inventory) | WITHDRAWN | UNVERIFIED | ... (anything but VERIFIED is refused)
    platform: str = ""
    os_version: str = ""
    maintenance: bool = False
    source: str = ""
    reason: str = ""

    @property
    def admitted(self) -> bool:
        return self.state == "VERIFIED"

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("device", "state", "platform", "os_version", "maintenance", "source", "reason")}


class InventoryAdmission:
    """Authoritative admission.  ``inventory()`` -> ``{name: {"platform": ...}}`` (default: the health inventory of managed devices);
    ``lifecycle(name)`` -> ``{"state": ..., "withdrawn": bool, "maintenance": bool}`` or ``None`` (no information).  A device absent from the
    inventory is UNKNOWN (not probe-able).  NMAS has no persisted per-device lifecycle model, so withdrawal/maintenance only apply when a provider is wired."""

    def __init__(self, *, inventory: Callable[[], dict] | None = None, lifecycle: Callable[[str], dict | None] | None = None):
        self._inventory, self._lifecycle = inventory, lifecycle

    def _load(self) -> dict:
        if self._inventory is not None:
            return self._inventory()
        from core.services.health import inventory   # lazy: needs Django settings
        return inventory.managed_devices()

    def resolve(self, devices: list[str]) -> dict[str, DeviceAdmission]:
        try:
            known = self._load()
            source = "inventory"
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - an unreadable inventory admits nobody
            return {d: DeviceAdmission(d, "UNKNOWN", source="inventory", reason=f"inventory unavailable: {type(exc).__name__}") for d in devices}
        out = {}
        for d in devices:
            entry = known.get(d)
            if entry is None:
                out[d] = DeviceAdmission(d, "UNKNOWN", source=source, reason="device is not in the authoritative inventory")
                continue
            life = self._lifecycle(d) if self._lifecycle else None
            state, maint, reason = "VERIFIED", False, ""
            if life:
                maint = bool(life.get("maintenance"))
                if life.get("withdrawn"):
                    state, reason = "WITHDRAWN", "device is withdrawn"
                elif life.get("state") and str(life["state"]).upper() not in col.ADMITTED_STATES | {"VERIFIED"}:
                    state, reason = str(life["state"]).upper(), f"lifecycle state {life['state']}"
            out[d] = DeviceAdmission(d, state, platform=str(entry.get("platform") or ""), os_version=str(entry.get("os_version") or ""), maintenance=maint,
                                     source=source + ("+lifecycle" if self._lifecycle else ""), reason=reason)
        return out


# ------------------------------------------------------------------------------------------------------------------ dependencies
@dataclass
class RuntimeDeps:
    """Everything injectable.  Defaults fail closed: with no transport/session/feed the corresponding evidence is UNAVAILABLE."""

    admission: InventoryAdmission = field(default_factory=InventoryAdmission)
    cli_transport: Callable[[DeviceAdmission], Any] | None = None          # -> object with execute(rendered)->str and optional provenance()
    diagnostic_worker: Callable[[DeviceAdmission, dict], Any] | None = None  # -> typed worker transport; requires a live handoff context
    snmp_session: Callable[[DeviceAdmission], Any] | None = None           # -> object with walk(oid)/get(oid)
    syslog_lines: Callable[[DeviceAdmission], Any] | None = None           # -> iterable of (line, received_at)
    gnmi_getter: Callable[[DeviceAdmission], Callable[[list], list]] | None = None
    gnmi_paths: tuple = ("/interfaces/interface/state",)
    sources: bl.BaselineSources | None = None
    capability_probe: Callable[[str, str], dict] | None = None
    raw_store: Any = None
    flow_input: Callable[[DeviceAdmission], FlowRuntimeInput | None] | None = None  # deployment-owned receiver + authorized selector
    syslog_window_s: int = 3600
    dns_runner: Callable[[DeviceAdmission], Any] | None = None             # -> authorized read-only DNS runner (adapters.dns.DnsRunner); None => DNS keys are NOT_CONFIGURED gaps
    dns_context: Any = None                                                  # adapters.dns.DnsContext (split-horizon vantage servers, extra authorized servers)
    probe_runner: Callable[[DeviceAdmission], Any] | None = None           # -> authorized active-probe runner (adapters.probes.ProbeRunner); None => service.probe/path.trace are NOT_CONFIGURED gaps (no default socket runner exists)
    probe_context: Any = None                                                # adapters.probes.ProbeContext (case-bound authorization, admitted sources, destinations, ports, address book)
    forwarding_context: Any = None                                           # adapters.forwarding.ForwardingContext (next-hop owners, gateways); None => next_hop_device unresolved
    fib_source: Callable[[DeviceAdmission], Any] | None = None             # -> injected read-only independent forwarding-table reader (read(request)->fib-source/1 document); None => route.fib stays an explicit NOT_CONFIGURED gap
    qos_source: Callable[[DeviceAdmission], Any] | None = None             # -> injected read-only QoS reader (read(request)->qos-source/1 document); None => qos.state is an explicit NOT_CONFIGURED gap (no default reader)
    phy_source: Callable[[DeviceAdmission], Any] | None = None             # -> injected read-only physical-state reader (read(request)->physical-source/1 document); None => transceiver/FEC/L1-event keys are explicit NOT_CONFIGURED gaps (no default reader)
    phy_context: Any = None                                                  # adapters.physical.PhysicalContext (link map naming the peer end); None => only the target end is read
    proto_source: Callable[[DeviceAdmission], Any] | None = None           # -> injected read-only routing-protocol reader (read(request)->protocol-source/1 document); None => capability.protocol / protocol.config / routing.neighbor.detail are explicit NOT_CONFIGURED gaps (no default reader)
    l2_context: Any = None                                                   # adapters.l2.L2Context (MAC history); None => MAC movement stays UNKNOWN
    acl_context: Any = None                                                  # adapters.acl.AclContext (counter history); None => ACL counter deltas stay UNKNOWN
    stp_context: Any = None                                                  # adapters.stp.StpContext (history + vlan aliases); None => no windowed STP facts
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)   # noqa: E731


# ------------------------------------------------------------------------------------------------------------------ mapping
def _subject(o: dict) -> str:
    t = o.get("target") or {}
    return t.get("interface") or t.get("neighbor") or t.get("vlan") or t.get("dns") or t.get("probe") or t.get("protocol") or ""


def _src(o: dict) -> str:
    s = o.get("source") or {}
    return f"{str(s.get('source_type') or '').lower()}:{s.get('transport') or ''}"


def _base(o: dict, key: str, subject: str, value: Any, *, device: str, run_key: str, unit_id: str, disc: str = "", unit: str | None = None, quality: str | None = None) -> dict:
    stored = join_key(key, subject)
    q = quality or QUALITY[o["quality"]]
    parser = o.get("parser") or {}
    out = {"key": stored, "target": device, "observed_at": o["observed_at"], "source": _src(o), "quality": q,
           "basis": "DERIVED" if o.get("evidence_class") == nz.EvidenceClass.INTENT else "OBSERVED", "value": value,
           "unit": o.get("unit", "") if unit is None else unit, "max_age_seconds": int((o.get("freshness") or {}).get("max_age_s") or 300),
           "confidence": float(o.get("confidence", 0.0)), "parser_version": f"{parser.get('id', '')}@{parser.get('version', '')}",
           "redaction_status": o.get("redaction_status", "NOT_APPLICABLE"),
           "dedupe_key": _h(run_key, device, unit_id, stored, disc, n=32)}
    if o.get("raw_hash"):
        out["raw_hash"] = o["raw_hash"]
    return out


def map_observations(s2_obs: list[dict], *, device: str, run_key: str, unit_id: str, window_s: int = 3600, forwarding: Any = None, flow: dict | None = None) -> list[dict]:
    """Collector observations of ONE evidence unit -> engine-ingestible ``observation/1`` dicts (see module docstring)."""
    out: list[dict] = []
    addrs: dict[str, list] = {}
    events: dict[str, list] = {}
    sysev: list[dict] = []
    rate_ifs: dict[str, dict] = {}
    resets: dict[str, dict] = {}
    tables: list[dict] = []
    nbrs: list[dict] = []
    fibs: list[dict] = []
    for o in s2_obs:
        if not o.get("observed_at") or QUALITY[o["quality"]] == "MISSING":
            out.append(missing_obs(o["key"], device, f"PARSE_FAILED: observation has no usable time/quality ({o['quality']})", o.get("observed_at") or "", run_key, unit_id,
                                   source=_src(o)))
            continue
        key, sub = o["key"], _subject(o)
        if key == "route.fib.table":
            fibs.append(o)
            continue
        if key == "qos.attachment":      # the ONLY producer of qos.state values; matches_flow-style claims were discarded by normalization
            v = o["value"]
            out.append(_base(o, "qos.state", f"{v['interface']}-{v['direction']}", v, device=device, run_key=run_key, unit_id=unit_id, disc=_h(sorted((o.get("target") or {}).items())), unit=""))
            continue
        if key == "route.table":
            tables.append(o)
            continue
        if key == "neighbor.entry":
            nbrs.append(o)
            continue
        if key in ("acl.rules", "acl.attachment"):      # joined across the two ACL commands of one bundle by join_acl_observations (never mapped alone)
            continue
        if key in ("mac.table", "l2.port") and (o.get("value") or {}).get("uncertain"):
            # HC08/HC09 read only the headline fields: uncertain history/partial tables are retained for audit but can never become PASS or FAULT.
            out.append(_base(o, key, sub, o["value"], device=device, run_key=run_key, unit_id=unit_id, quality="UNTRUSTED"))
            continue
        if key.startswith("stp.") and (
            "PARTIAL_PARSE" in o.get("flags", []) or
            (key == "stp.state" and o.get("value", {}).get("uncertain"))
        ):
            # RB04 currently consumes the complete state object, without per-field
            # uncertainty handling. Retain the normalized value for audit, but do
            # not let incomplete history/ports become a healthy verdict.
            out.append(_base(o, key, sub, o["value"], device=device, run_key=run_key, unit_id=unit_id, quality="UNTRUSTED"))
            continue
        if key in DIRECT_KEYS and sub:
            out.append(_base(o, key, sub, o["value"], device=device, run_key=run_key, unit_id=unit_id))
        elif key == "interface.address" and sub:
            addrs.setdefault(sub, []).append(o)
        elif key.startswith("interface.rate.") and sub:
            out.append(_base(o, key, sub, o["value"], device=device, run_key=run_key, unit_id=unit_id))
            rate_ifs.setdefault(sub, o)
        elif key == "interface.counter_event" and sub:
            resets[sub] = o
        elif key in ("routing.ospf.neighbor_state", "routing.bgp.neighbor_state"):
            t = o["target"]
            nbr = str(t.get("neighbor") or "")
            if not nbr:
                continue
            val = {"state": NEIGHBOR_STATE.get(str(o["value"]), str(o["value"]).title()), "protocol": t.get("protocol") or key.split(".")[1], "vrf": t.get("vrf"),
                   "interface": t.get("interface", ""), "family": t.get("family"), "neighbor_id": nbr, "raw_state": o["value"]}
            out.append(_base(o, "routing.neighbor", nbr, val, device=device, run_key=run_key, unit_id=unit_id, disc=f"{t.get('protocol')}|{t.get('vrf')}", unit=""))
        elif key == "interface.link_event" and sub:
            events.setdefault(sub, []).append(o)
        elif key.startswith(("syslog.", "stp.", "routing.ospf.adjacency", "routing.bgp.adjacency", "interface.optics")) and o.get("extra"):
            sysev.append(o)
        else:   # retained, not consumed by any runbook
            out.append(_base(o, key, sub, o["value"], device=device, run_key=run_key, unit_id=unit_id, disc=_h(sorted((o.get("target") or {}).items()))))
    if fibs:
        out += _map_fib(fibs, device=device, run_key=run_key, unit_id=unit_id, flow=flow, ctx=forwarding)
    if tables or nbrs:
        out += _map_forwarding(tables, nbrs, device=device, run_key=run_key, unit_id=unit_id, flow=flow, ctx=forwarding)
    for sub, items in addrs.items():
        v4 = [i["value"] for i in items if ":" not in str(i["value"])]
        v6 = [i["value"] for i in items if ":" in str(i["value"])]
        first = max(items, key=lambda i: i["observed_at"])
        out.append(_base(first, "interface.address", sub, {"ipv4": v4[0] if v4 else None, "ipv6": v6[0] if v6 else None, "addresses": sorted(map(str, v4 + v6))},
                         device=device, run_key=run_key, unit_id=unit_id, unit=""))
    for sub, items in events.items():
        items.sort(key=lambda i: i["observed_at"])
        evs = [{"at": i["observed_at"], "state": str(i["value"]), "reason": (i.get("extra") or {}).get("message", "")[:200], "occurrences": (i.get("extra") or {}).get("occurrences", 1)}
               for i in items]
        out.append(_base(items[-1], "interface.link_event", sub, {"window_s": window_s, "events": evs, "source": "syslog"}, device=device, run_key=run_key, unit_id=unit_id,
                         disc=_h([e["at"] for e in evs]), unit=""))
    if sysev:
        sysev.sort(key=lambda i: i["observed_at"])
        evs = [{"at": i["observed_at"], "type": (i.get("extra") or {}).get("event_type", ""), "key": i["key"], "state": str(i["value"])[:200],
                "message": (i.get("extra") or {}).get("message", "")[:200], "severity": (i.get("extra") or {}).get("severity")} for i in sysev]
        out.append(_base(sysev[-1], "syslog.system_events", "", {"events": evs, "window_s": window_s}, device=device, run_key=run_key, unit_id=unit_id,
                         disc=_h([e["at"] for e in evs]), unit=""))
    # counter_reset: True only from a collector-detected RESET; False only when a monotonic rate sample proves no reset in the interval.
    for sub in set(resets) | set(rate_ifs):
        ro = resets.get(sub)
        if ro is not None:
            is_reset = str(ro["value"]) == "reset"
            out.append(_base(ro, "interface.counter_reset", sub, {"reset": is_reset, "event": ro["value"], "counter": (ro.get("extra") or {}).get("counter")},
                             device=device, run_key=run_key, unit_id=unit_id, unit=""))
        else:
            out.append(_base(rate_ifs[sub], "interface.counter_reset", sub, {"reset": False, "event": "rate-sample-ok"}, device=device, run_key=run_key, unit_id=unit_id, unit="",
                             quality="PARTIAL"))
    return out


def join_acl_observations(s2_obs: list[dict], *, device: str, run_key: str) -> dict[str, list[dict]]:
    """``acl.rules`` x ``acl.attachment`` of ONE bundle -> engine ``acl.counters@<interface>-<direction>`` observations, keyed by the evidence id of the
    rules observation they are stored under.  Attachment comes ONLY from ``acl.attachment``; an attached ACL with no usable rules (or the reverse) yields
    nothing but an explicit gap.  Unattached ACLs produce no observation.  Partial/uncertain inputs are held UNTRUSTED, never GOOD."""
    rules = {(o["value"]["acl"], o["value"]["af"]): o for o in s2_obs if o.get("key") == "acl.rules" and o.get("observed_at") and QUALITY[o["quality"]] != "MISSING"}
    out: dict[str, list[dict]] = {}
    for a in (o for o in s2_obs if o.get("key") == "acl.attachment"):
        av = a["value"]
        r = rules.get((av["acl"], av["af"]))
        subject = f"{av['interface']}-{av['direction']}"
        key = join_key("acl.counters", subject)
        unit = _h("acl-join", a["source"]["evidence_id"] if a.get("source") else "")
        if r is None or not a.get("observed_at"):
            out.setdefault((a.get("source") or {}).get("evidence_id", ""), []).append(
                missing_obs(key, device, f"EMPTY: ACL {av['acl']} is attached to {subject} but its rules were not collected", a.get("observed_at") or "", run_key, unit, source=_src(a)))
            continue
        rv = r["value"]
        uncertain = list(rv.get("uncertain", [])) + list(av.get("uncertain", []))
        value = {"schema": "nmas.acl.counters/1", "acl": av["acl"], "interface": av["interface"], "direction": av["direction"], "af": av["af"], "vrf": av.get("vrf"),
                 "attachment_source": "acl.attachment", "attachment_evidence": (a.get("source") or {}).get("evidence_id"), "sample_interval_s": rv.get("sample_interval_s"),
                 "rules": rv["rules"], "complete": bool(rv.get("complete")) and not av.get("uncertain"), "uncertain": uncertain, "unsupported_rules": rv.get("unsupported_rules", [])}
        bad = QUALITY[r["quality"]] != "GOOD" or QUALITY[a["quality"]] != "GOOD" or not value["complete"]
        row = _base(r, "acl.counters", subject, value, device=device, run_key=run_key, unit_id=unit, disc=av["acl"], unit="", quality="UNTRUSTED" if bad else None)
        out.setdefault((r.get("source") or {}).get("evidence_id", ""), []).append(row)
    return out


def _map_forwarding(tables: list[dict], nbrs: list[dict], *, device: str, run_key: str, unit_id: str, flow: dict | None, ctx: Any) -> list[dict]:
    """``route.table`` / ``neighbor.entry`` -> ``route.rib@<prefix>`` (HC15/HC24), ``arp.entry@<address>`` (HC10) and small table summaries.  FIB is never produced here."""
    out: list[dict] = []
    for t in tables:
        v = t["value"]
        out.append(_base(t, "route.table", f"{v['vrf']}/{v['family']}", {k: v[k] for k in ("vrf", "family", "route_count", "complete", "uncertain", "table_kind", "fib_evidence")},
                         device=device, run_key=run_key, unit_id=unit_id, unit=""))
    when = (tables or nbrs)[0]["observed_at"]
    for q in fwd_ad.route_queries(flow, ctx) if tables else []:
        value, reason = fwd_ad.rib_lookup(tables, q, device=device, ctx=ctx)
        key = join_key("route.rib", q.prefix)
        if value is None:
            out.append(missing_obs(key, device, f"EMPTY: {reason}", when, run_key, unit_id, source=_src(tables[0])))
            continue
        anchor = next(t for t in tables if t["value"]["vrf"] == q.vrf and t["value"]["family"] == q.family)
        out.append(_base(anchor, "route.rib", q.prefix, value, device=device, run_key=run_key, unit_id=unit_id, disc=f"{q.vrf}|{q.family}", unit=""))
    if nbrs:
        vrf = str((flow or {}).get("vrf") or "default")
        vals = fwd_ad.neighbor_values(nbrs, vrf=vrf)
        for sub, (value, quality, flags) in vals.items():
            anchor = next(n for n in nbrs if n["value"]["address"] == value["address"] and n["value"]["vrf"] == value["vrf"])
            row = _base(anchor, "arp.entry", sub, value, device=device, run_key=run_key, unit_id=unit_id, disc=value["interface"], unit="", quality=quality)
            if flags:     # the engine observation contract has no flags field: keep them inside the value so they stay auditable
                row["value"] = {**row["value"], "flags": flags}
            out.append(row)
        fams = {n["value"]["family"] for n in nbrs}
        complete = all(n["value"].get("complete") for n in nbrs)
        for gw in fwd_ad.gateway_subjects(device, ctx):
            fam = "ipv6" if ":" in gw else "ipv4"
            if gw not in vals and fam in fams:
                why = "no ARP/ND cache entry" if complete else "no ARP/ND cache entry in an incomplete table"
                out.append(missing_obs(join_key("arp.entry", gw), device, f"EMPTY: {why} for {gw}; a cache miss is not proof of a resolution failure", when, run_key, unit_id,
                                       source=_src(nbrs[0])))
    return out


def _map_fib(fibs: list[dict], *, device: str, run_key: str, unit_id: str, flow: dict | None, ctx: Any) -> list[dict]:
    """``route.fib.table`` (independent forwarding source) -> ``route.fib@<prefix>`` (HC16) + a table summary.  Only this path may produce ``route.fib`` values."""
    out: list[dict] = []
    for t in fibs:
        v = t["value"]
        out.append(_base(t, "route.fib.table", f"{v['vrf']}/{v['family']}", {k: v[k] for k in ("vrf", "family", "coverage", "complete", "entry_count", "uncertain", "table_kind", "fib_evidence", "source", "provenance")},
                         device=device, run_key=run_key, unit_id=unit_id, unit=""))
    for q in fwd_ad.route_queries(flow, ctx):
        value, reason = fwd_ad.fib_lookup(fibs, q)
        key = join_key("route.fib", q.prefix)
        if value is None:
            out.append(missing_obs(key, device, f"EMPTY: {reason}", fibs[0]["observed_at"], run_key, unit_id, source=_src(fibs[0])))
            continue
        anchor = next(t for t in fibs if t["value"]["vrf"] == q.vrf and t["value"]["family"] == q.family)
        out.append(_base(anchor, "route.fib", q.prefix, value, device=device, run_key=run_key, unit_id=unit_id, disc=f"{q.vrf}|{q.family}", unit=""))
    return out


def missing_obs(key: str, device: str, reason: str, observed_at: str, run_key: str, unit_id: str, *, source: str = "runtime") -> dict:
    return {"key": key, "target": device, "observed_at": observed_at or c.iso(datetime.now(timezone.utc)), "source": source, "quality": "MISSING", "basis": "OBSERVED",
            "is_missing_data": True, "missing_reason": c.redact_text(reason)[0][:255], "stage_decision": "UNKNOWN",
            "dedupe_key": _h(run_key, device, unit_id, key, reason, n=32)}


# ------------------------------------------------------------------------------------------------------------------ provider
class CollectorProvider:
    """``engine.EvidenceProvider`` backed by the canonical collectors.  One ``collection_bundle/1`` is produced per evidence unit (command / poll /
    window) so every raw source keeps its own hash, pointer, parser identity and gateway provenance; idempotency keys derive from ``run_key`` (not from
    timestamps), so a restarted run reuses finished runs and a device whose manifest run is final is NOT contacted again."""

    def __init__(self, actor: repo.Actor, case, deps: RuntimeDeps, admissions: dict[str, DeviceAdmission], budget: RuntimeBudget, run_key: str,
                 *, worker_context: dict | None = None):
        self.actor, self.case, self.deps, self.adm, self.budget, self.run_key = actor, case, deps, admissions, budget, run_key
        self.raw_store = deps.raw_store or col.InMemoryRawStore()
        self.worker_context = dict(worker_context or {})
        self.probe = deps.capability_probe or caps.make_capability_probe()
        self.started = deps.clock()
        self.report: dict[str, Any] = {"devices": {}, "contacted": [], "resumed": [], "gaps": {}}
        kw = dict(budget=budget.collector_budget(), clock=deps.clock, sleep=deps.sleep, now=deps.now, raw_store=self.raw_store, capability_probe=self.probe,
                  adapter="runtime")
        self.cli = col.CliCollector(**kw)
        self.snmp = col.SnmpCollector(**kw)
        self.syslog = col.SyslogCollector(**kw)
        self.cli.stp_context = deps.stp_context
        self.cli.l2_context = deps.l2_context
        self.cli.acl_context = deps.acl_context
        self.gnmi = col.GnmiCollector(**kw)
        self.dns = col.DnsCollector(**kw)
        self.probe = col.ProbeCollector(**kw)
        self.probe.context = deps.probe_context
        self.flow = col.FlowCollector(**kw)
        self.fib = col.FibCollector(**kw)
        self.qos = col.QosCollector(**kw)
        self.phy = col.PhysicalCollector(**kw)
        self.proto = col.ProtocolCollector(**kw)
        self._kw = kw

    # -- helpers
    def _prefix(self, device: str) -> str:
        return f"rt-{_h(self.run_key, n=12)}-{_h(device, n=8)}-"

    def _key(self, device: str, unit_id: str) -> str:
        return self._prefix(device) + unit_id

    def _target(self, info: DeviceAdmission) -> col.Target:
        return col.Target(device=info.device, platform=info.platform, os_version=info.os_version, lifecycle_state="VERIFIED", verified=True,
                          maintenance=info.maintenance)

    def _resumable(self, device: str) -> bool:
        manifest = m.TsCollectionRun.objects.filter(case=self.case, idempotency_key=self._key(device, "manifest")).first()
        return bool(manifest and manifest.status in m.TsCollectionRun.FINAL)

    @staticmethod
    def wanted_cli(platform: str, wanted: list[str]) -> list[str]:
        fam = {"ceos": "ceos", "iosxe": "iosxe", "linux": "linux"}.get(nz.canonical_platform(platform), "")
        keys: list[str] = []
        for w in wanted:
            for canon, per in CANON_TO_CLI.items():
                if (w == canon or w.startswith(canon + ".")) and fam:
                    keys += [k for k in per.get(fam, ()) if k not in keys]
        return keys

    # -- engine entry
    def collect(self, case_id: str, device: str, wanted, now: datetime) -> list[dict]:  # pylint: disable=too-many-branches  # per-source admission / budget / failure accounting kept in one auditable sequence
        want_config = cfg_ad.requested(wanted)
        wanted = sorted(w for w in wanted if w not in BASELINE_KEYS)
        info = self.adm.get(device)
        if info is None or not info.admitted:
            raise repo.TargetRefused(f"{device}: not admitted ({info.state if info else 'UNKNOWN'})")
        if self.deps.clock() - self.started >= self.budget.max_seconds:
            raise TimeoutError("BUDGET_EXCEEDED: runtime wall-clock budget exhausted before contacting " + device)
        if self._resumable(device):
            self.report["resumed"].append(device)
            return []
        self.report["contacted"].append(device)
        bundles: list[dict] = []
        s2: list[dict] = []
        target = self._target(info)
        cli_keys = self.wanted_cli(info.platform, wanted)
        fams = fwd_ad.wanted_families(self.case.flow_scope, self.deps.forwarding_context)
        if "ipv6" not in fams:
            cli_keys = [k for k in cli_keys if k not in col.FORWARDING_V6_KEYS]
        if "ipv4" not in fams:
            cli_keys = [k for k in cli_keys if k not in ("ip_route", "route4", "arp")]
        covered: set[str] = set()
        if cli_keys:
            if self.deps.diagnostic_worker and self.worker_context:
                transport = self.deps.diagnostic_worker(info, self.worker_context)
            else:
                transport = self.deps.cli_transport(info) if self.deps.cli_transport else None
            if transport is None:
                s2.append(self._unavailable(target, col.SourceType.CLI, "no CLI transport is configured for this device in this runtime", cli_keys))
            else:
                s2.append(self.cli.collect(target, cli_keys, transport, transport_name=type(transport).__name__.lower()))
            for k in cli_keys:
                covered.update(CLI_KEY_CANON.get(k, ()))
        if want_config:      # running config is collected BEFORE the engine's baseline stage so that configs() can compare it with golden
            s2.extend(self._config_snapshot(info, target, len(cli_keys)))
        if any(w.startswith(("interface.rate", "interface.counter")) for w in wanted) or any(w.startswith("interface.") for w in wanted):
            session = self.deps.snmp_session(info) if self.deps.snmp_session else None
            if session is not None:
                s2.append(self.snmp.poll(target, session))
        if any(w.startswith(("interface.link_event", "syslog.")) for w in wanted):
            lines = self.deps.syslog_lines(info) if self.deps.syslog_lines else None
            if lines is not None:
                s2.append(self.syslog.collect(target, lines))
        if self.deps.gnmi_getter is not None and any(w.startswith("interface.") for w in wanted):
            getter = self.deps.gnmi_getter(info)
            if getter is not None:
                s2.append(self.gnmi.get(target, list(self.deps.gnmi_paths), getter))
        dns_requests = dns_ad.requests_for_device(dict(self.case.service_intent.get("target", {})), device, wanted, self.deps.dns_context)
        if dns_requests:
            runner = self.deps.dns_runner(info) if self.deps.dns_runner else None
            if runner is None:
                s2.append(self._dns_unavailable(target, dns_requests))
            else:
                s2.append(self.dns.collect(target, dns_requests, runner, allowed_servers=dns_ad.allowed_servers(dict(self.case.service_intent.get("target", {})), self.deps.dns_context),
                                           transport_name=type(runner).__name__.lower()))
            covered.update(dns_ad.served_keys(dns_requests))
        probe_requests = probe_ad.requests_for_device(dict(self.case.flow_scope or {}), device, wanted, self.deps.probe_context)
        if probe_requests:
            prunner = self.deps.probe_runner(info) if self.deps.probe_runner else None
            if prunner is None:
                s2.append(self._probe_unavailable(target, probe_requests))
            else:
                s2.append(self.probe.collect(target, probe_requests, prunner, probe_ad.policy_for(dict(self.case.flow_scope or {}), self.case.case_id, self.deps.probe_context),
                                             transport_name=type(prunner).__name__.lower()))
            covered.update(probe_ad.served_keys(probe_requests))
        fib_reqs = fwd_ad.fib_requests(self.case.flow_scope, self.deps.forwarding_context) if "route.fib" in wanted else []
        if fib_reqs and self.deps.fib_source is not None:
            reader = self.deps.fib_source(info)
            if reader is not None:
                s2.append(self.fib.collect(target, fib_reqs, reader, transport_name=type(reader).__name__.lower()))
        if "qos.state" in wanted and self.deps.qos_source is not None:
            qreader = self.deps.qos_source(info)
            if qreader is not None:
                s2.append(self.qos.collect(target, [qos_ad.qos_request(self.case.flow_scope)], qreader, transport_name=type(qreader).__name__.lower()))
                covered.add("qos.state")      # the collector's own records (values or engine_key-bound missing) answer the key
        phy_reqs = phy_ad.requests_for_device(dict(self.case.service_intent.get("target", {})), device, wanted, self.deps.phy_context)
        if phy_reqs and self.deps.phy_source is not None:
            preader = self.deps.phy_source(info)
            if preader is not None:
                s2.append(self.phy.collect(target, phy_reqs, preader, transport_name=type(preader).__name__.lower()))
                covered.update(phy_ad.PHYSICAL_KEYS & set(wanted))   # the collector's own records (values or key+subject-bound missing) answer these keys
        proto_reqs = proto_ad.requests_for_device(dict(self.case.service_intent.get("target", {})), device, wanted, tuple(self.case.affected_scope.get("devices", ())))
        if proto_reqs and self.deps.proto_source is not None:
            prreader = self.deps.proto_source(info)
            if prreader is not None:
                s2.append(self.proto.collect(target, proto_reqs, prreader, transport_name=type(prreader).__name__.lower()))
                covered.update(proto_ad.served_keys(proto_reqs) & set(wanted))   # the collector's own records (values or key+subject-bound missing) answer these keys
        flow_wanted = [w for w in wanted if w.startswith("flow.")]
        if flow_wanted:
            binding = self.deps.flow_input(info) if self.deps.flow_input else None
            if binding is not None:
                s2.append(binding.collect(self.flow, target, limit=self.budget.max_records))
            # Wire volume is never a service-health measurement, even with sampling=1.
            gaps_for_flow = [w for w in flow_wanted if w == "flow.health" or binding is None]
            if gaps_for_flow:
                b = self._unavailable(target, col.SourceType.NETFLOW,
                    "NOT_CONFIGURED: deployment-owned flow input is absent" if binding is None else
                    "UNKNOWN: wire volume/sequence gaps cannot measure production loss, latency or availability", gaps_for_flow)
                for mr, key in zip(b["missing"], gaps_for_flow):
                    mr["reason"] = nz.Missing.NOT_CONFIGURED if binding is None else nz.Missing.EMPTY
                    mr["extra"] = {"engine_key": key}
                s2.append(b)
                covered.update(gaps_for_flow)
        # capability gaps: wanted keys no configured collector can serve -> explicit missing records (never values)
        served = set(covered)
        for b in s2:
            served.update(o["key"] for o in b["observations"])
        gaps = [w for w in wanted if w not in served and not any(w == s or s.startswith(w + ".") or w.startswith(s + ".") for s in served)]
        for i, b in enumerate(s2):
            bundles += self._bridge(b, info, i)
        if "route.fib" in wanted:     # explicit, subject-bound FIB gap per asked prefix not answered by the independent source: RIB is never promoted to FIB evidence
            produced = {o["key"] for b in bundles for o in b["observations"]}
            fib_keys = [join_key("route.fib", q.prefix) for q in fwd_ad.route_queries(self.case.flow_scope, self.deps.forwarding_context)]
            fib_keys = [k for k in fib_keys if k not in produced]
            if fib_keys:
                why = (fwd_ad.FIB_GAP_REASON if self.deps.fib_source is None else
                       "UNKNOWN: the independent forwarding source produced no usable evidence for this prefix (see the collector run); the FIB is never derived from the RIB")
                bundles.append(self._gap_bundle(info, fib_keys, {k: why for k in fib_keys}))
        if "qos.state" in gaps:
            bundles.append(self._gap_bundle(info, ["qos.state"], {"qos.state": qos_ad.QOS_GAP_REASON if self.deps.qos_source is None else
                           "UNKNOWN: the injected QoS source produced no usable attachment evidence (see the collector run)"}))
            gaps = [g for g in gaps if g != "qos.state"]
        phy_gaps = [g for g in gaps if g in phy_ad.PHYSICAL_KEYS]
        if phy_gaps:
            why = phy_ad.gap_reason(self.deps.phy_source is not None, bool(phy_reqs))
            bundles.append(self._gap_bundle(info, phy_gaps, {g: why for g in phy_gaps}))
            gaps = [g for g in gaps if g not in phy_ad.PHYSICAL_KEYS]
        proto_gaps = [g for g in gaps if g in proto_ad.PROTOCOL_KEYS]
        if proto_gaps:
            why = proto_ad.gap_reason(dict(self.case.service_intent.get("target", {})), self.deps.proto_source is not None, bool(proto_reqs))
            bundles.append(self._gap_bundle(info, proto_gaps, {g: why for g in proto_gaps}))
            gaps = [g for g in gaps if g not in proto_ad.PROTOCOL_KEYS]
        if gaps:
            bundles.append(self._gap_bundle(info, gaps))
        self.report["gaps"][device] = gaps
        bundles.append(self._manifest(info, len(bundles)))
        return bundles

    # -- collector bundle builders
    def _config_snapshot(self, info: DeviceAdmission, target: col.Target, used_commands: int) -> list[dict]:
        """Bounded read-only running-config collection for one admitted device (capability/budget/transport refusals become explicit gaps)."""
        key = cfg_ad.snapshot_key(info.platform)
        st = col.SourceType.CONFIG_SNAPSHOT
        if key is None:
            return [self._unavailable(target, st, f"no catalogued running-config read for platform {info.platform or '?'}; running config is UNKNOWN", ["running_config"])]
        if used_commands + 1 > self.budget.max_commands:
            b = self._unavailable(target, st, "BUDGET_EXCEEDED: command budget is spent before the running-config read", [key])
            for mr in b["missing"]:
                mr["reason"] = nz.Missing.BUDGET_EXCEEDED
            return [b]
        gate = cfg_ad.admission(self.cli, target)
        if not gate.ok:
            b = self._unavailable(target, st, f"{gate.code}: {gate.detail}", [key])
            for mr in b["missing"]:
                mr["reason"] = gate.code
            return [b]
        transport = self.deps.cli_transport(info) if self.deps.cli_transport else None
        if transport is None:
            b = self._unavailable(target, st, "NOT_CONFIGURED: no CLI transport is configured for this device in this runtime", [key])
            for mr in b["missing"]:
                mr["reason"] = nz.Missing.NOT_CONFIGURED
            return [b]
        return [cfg_ad.collect(self.cli, target, transport, transport_name=type(transport).__name__.lower())]

    def _unavailable(self, target: col.Target, source_type: str, detail: str, cmds: list[str]) -> dict:
        now = self.deps.now()
        rec = [nz.missing_record(nz.Missing.UNSUPPORTED_PLATFORM, source_type=source_type, device=target.device, detail=detail, command=k, observed_at=now) for k in cmds]
        run = {"collector": "runtime", "adapter": "runtime", "collector_version": RUNTIME_VERSION, "device": target.device, "source_type": source_type, "status": "FAILED",
               "command_or_api": cmds, "started_at": c.iso(now), "finished_at": c.iso(now), "retries": 0, "timeout_s": 0, "rate_budget": {}, "privileges": "read-only",
               "flags": [], "gateway": None, "run_id": "run-" + _h(target.device, source_type, "unavailable")}
        return {"run": run, "evidence": [], "observations": [], "missing": rec, "coverage": {}}

    def _dns_unavailable(self, target: col.Target, requests: list) -> dict:
        now = self.deps.now()
        rec = [nz.missing_record(nz.Missing.NOT_CONFIGURED, source_type=col.SourceType.DNS_QUERY, device=target.device, command=r.command(), observed_at=now,
                                 detail="no authorized DNS runner is configured for this device in this runtime; DNS evidence is UNKNOWN (nothing is queried or invented)",
                                 extra={"engine_key": r.engine_key()}) for r in requests]
        run = {"collector": "runtime", "adapter": "runtime", "collector_version": RUNTIME_VERSION, "device": target.device, "source_type": col.SourceType.DNS_QUERY, "status": "FAILED",
               "command_or_api": [r.command() for r in requests], "started_at": c.iso(now), "finished_at": c.iso(now), "retries": 0, "timeout_s": 0, "rate_budget": {},
               "privileges": "read-only", "flags": [], "gateway": None, "run_id": "run-" + _h(target.device, "dns", "unavailable")}
        return {"run": run, "evidence": [], "observations": [], "missing": rec, "coverage": {}}

    def _probe_unavailable(self, target: col.Target, requests: list) -> dict:
        now = self.deps.now()
        rec = [nz.missing_record(nz.Missing.NOT_CONFIGURED, source_type=col.SourceType.ACTIVE_PROBE, device=target.device, command=r.command(), observed_at=now,
                                 detail="no authorized active-probe runner is configured for this device in this runtime; probe evidence is UNKNOWN (nothing is sent or invented)",
                                 extra={"engine_key": r.engine_key()}) for r in requests]
        run = {"collector": "runtime", "adapter": "runtime", "collector_version": RUNTIME_VERSION, "device": target.device, "source_type": col.SourceType.ACTIVE_PROBE,
               "status": "FAILED", "command_or_api": [r.command() for r in requests], "started_at": c.iso(now), "finished_at": c.iso(now), "retries": 0, "timeout_s": 0,
               "rate_budget": {}, "privileges": "read-only", "flags": [], "gateway": None, "run_id": "run-" + _h(target.device, "probe", "unavailable")}
        return {"run": run, "evidence": [], "observations": [], "missing": rec, "coverage": {}}

    def _canon_for(self, command: str) -> tuple[str, ...]:
        cmd = str(command or "")
        for key, canon in CLI_KEY_CANON.items():
            for per in col.COMMAND_CATALOG.values():
                spec = per.get(key)
                if spec is not None and (cmd == key or cmd == (spec.command if isinstance(spec.command, str) else " ".join(spec.command))):
                    return canon
        return ()

    def _bridge(self, bundle: dict, info: DeviceAdmission, idx: int) -> list[dict]:
        run, device = bundle["run"], info.device
        evs = bundle["evidence"]
        out: list[dict] = []
        used_missing: set[int] = set()
        acl_joined = join_acl_observations(bundle["observations"], device=device, run_key=self.run_key)
        for e in evs:
            unit = _h(run["source_type"], e["command_or_api"], idx, n=16)
            mine = [o for o in bundle["observations"] if (o.get("source") or {}).get("evidence_id") == e["evidence_id"]]
            mapped = map_observations(mine, device=device, run_key=self.run_key, unit_id=unit, window_s=self.deps.syslog_window_s,
                                      forwarding=self.deps.forwarding_context, flow=self.case.flow_scope)
            mapped += acl_joined.get(e["evidence_id"], [])
            for i, mr in enumerate(bundle["missing"]):
                if mr.get("evidence_id") == e["evidence_id"] or (not mr.get("evidence_id") and mr.get("command_or_api") == e["command_or_api"]):
                    used_missing.add(i)
                    mapped += self._missing_for(mr, device, unit)
            ref = e["raw_ref"]
            text = getattr(self.raw_store, "items", {}).get(ref.get("hash"))
            gateway = e.get("gateway") or run.get("gateway")
            parser = e.get("parser") or {}
            ok = [o for o in mapped if not o.get("is_missing_data")]
            gaps = [o for o in mapped if o.get("is_missing_data")]
            status = "SUCCEEDED" if ok and not gaps and e["status"] in ("OK",) else ("PARTIAL" if ok else "FAILED")
            pointer = ref.get("pointer") or f"collector:{e['evidence_id']}"
            scope = {"runtime": RUNTIME_VERSION, "collector_evidence_id": e["evidence_id"], "raw_hash_as_received": ref.get("hash"), "raw_bytes": ref.get("bytes"),
                     "raw_pointer": pointer, "stored_hash": ref.get("stored_hash"), "parser": parser or None, "gateway": gateway, "live": bool(gateway and gateway.get("live")),
                     "transport": e.get("transport"), "adapter": e.get("adapter"), "collector_run_id": run.get("run_id"), "collector_status": e["status"],
                     "run_key": self.run_key, "redaction": e.get("redaction"), "platform": e.get("platform") or info.platform}
            if e["source_type"] == col.SourceType.CONFIG_SNAPSHOT:
                scope.update(cfg_ad.evidence_scope(e))
            if bundle.get("wire_ingest"):
                scope["wire_ingest"] = bundle["wire_ingest"]
                scope["collector_flags"] = run.get("flags", [])
                scope["normalized_flow"] = [{"key": o["key"], "value": o["value"], "quality": o["quality"],
                    "flags": o.get("flags", []), "extra": o.get("extra", {})} for o in mine]
            cmd = e["command_or_api"][:255]
            finished = e["collected_at"]
            bundle_doc = {
                "schema": "collection_bundle/1", "case_id": self.case.case_id, "collector": run["collector"], "adapter": e["adapter"], "adapter_version": e["adapter_version"],
                "idempotency_key": self._key(device, unit), "targets": [device], "command_or_api": cmd, "status": status, "observations": mapped,
                "started_at": e["started_at"], "finished_at": finished, "attempts": 1 + int(run.get("retries", 0)), "timeout_seconds": max(1, int(run.get("timeout_s") or 1)),
                "rate_budget": run.get("rate_budget") or {}, "privileges": "read-only",
                "raw": {"source_type": e["source_type"].lower(), "text": text, "pointer": pointer, "parser": parser.get("id", ""), "parser_version": str(parser.get("version", ""))}}
            # pre-store the evidence WITH its provenance scope using exactly the arguments ingest uses -> ingest returns this same row
            repo.store_evidence(self.actor, self.case, source_type=bundle_doc["raw"]["source_type"], device=device, command_or_api=cmd, adapter=e["adapter"],
                                adapter_version=e["adapter_version"], parser=bundle_doc["raw"]["parser"], parser_version=bundle_doc["raw"]["parser_version"],
                                collected_at=c.parse_time(finished), raw=text, raw_pointer=pointer, scope=scope,
                                quality="GOOD" if e["status"] == "OK" else "PARTIAL")
            out.append(bundle_doc)
        rest = [mr for i, mr in enumerate(bundle["missing"]) if i not in used_missing]
        if rest:     # refusals / failures with no evidence unit (admission denial, timeouts, budget)
            unit = _h(run["source_type"], "unevidenced", idx, n=16)
            mapped = []
            for mr in rest:
                mapped += self._missing_for(mr, device, unit)
            denied = (run.get("admission") or {}).get("ok") is False
            out.append({"schema": "collection_bundle/1", "case_id": self.case.case_id, "collector": run["collector"], "adapter": run["adapter"], "adapter_version": run["collector_version"],
                        "idempotency_key": self._key(device, unit), "targets": [device], "command_or_api": "; ".join(map(str, run["command_or_api"]))[:255] or run["source_type"],
                        "status": "DENIED" if denied else "FAILED", "observations": mapped, "started_at": run["started_at"], "finished_at": run["finished_at"],
                        "privileges": "read-only", "timeout_seconds": max(1, int(run.get("timeout_s") or 1)), "raw": {}})
        return out

    def _missing_for(self, mr: dict, device: str, unit: str) -> list[dict]:
        engine_key = (mr.get("extra") or {}).get("engine_key")
        canon = (engine_key,) if engine_key else self._canon_for(mr.get("command_or_api", "")) or (f"missing.{str(mr.get('source_type', '')).lower()}",)
        reason = f"{mr['reason']}: {mr.get('detail', '')}"
        keys = list(canon)
        subject = (mr.get("extra") or {}).get("subject")
        if engine_key and subject:      # physical source: the runbook asks for the interface-bound key
            keys.append(join_key(engine_key, subject))
        for k in canon:          # the runbook asks for subject-bound keys: a failed read must reach THOSE as the precise gap
            if k == "route.rib":
                keys += [join_key(k, q.prefix) for q in fwd_ad.route_queries(self.case.flow_scope, self.deps.forwarding_context)]
            elif k == "arp.entry":
                keys += [join_key(k, g) for g in fwd_ad.gateway_subjects(device, self.deps.forwarding_context)]
        return [missing_obs(k, device, reason, mr.get("recorded_at", ""), self.run_key, unit, source=str(mr.get("source_type", "")).lower()) for k in dict.fromkeys(keys)]

    def _gap_bundle(self, info: DeviceAdmission, gaps: list[str], reasons: dict | None = None) -> dict:
        now = c.iso(self.deps.now())
        obs = [missing_obs(k, info.device, (reasons or {}).get(k) or "UNSUPPORTED_PLATFORM: no canonical collector/transport in this runtime produced this key (collection is not attempted; absence is not evidence)",
                           now, self.run_key, "gaps", source="runtime") for k in gaps]
        return {"schema": "collection_bundle/1", "case_id": self.case.case_id, "collector": "runtime", "adapter": "runtime", "adapter_version": RUNTIME_VERSION,
                "idempotency_key": self._key(info.device, "gaps"), "targets": [info.device], "command_or_api": "capability-gaps", "status": "UNAVAILABLE", "observations": obs,
                "started_at": now, "finished_at": now, "privileges": "read-only", "timeout_seconds": 1, "raw": {}}

    def _manifest(self, info: DeviceAdmission, n: int) -> dict:
        now = c.iso(self.deps.now())
        return {"schema": "collection_bundle/1", "case_id": self.case.case_id, "collector": "runtime", "adapter": "runtime", "adapter_version": RUNTIME_VERSION,
                "idempotency_key": self._key(info.device, "manifest"), "targets": [info.device], "command_or_api": f"manifest:{n}", "status": "SUCCEEDED", "observations": [],
                "started_at": now, "finished_at": now, "privileges": "read-only", "timeout_seconds": 1, "raw": {}}


# ------------------------------------------------------------------------------------------------------------------ orchestration
def resolve_admission(actor: repo.Actor, case, deps: RuntimeDeps, budget: RuntimeBudget, now: datetime) -> dict[str, DeviceAdmission]:
    """Resolve authoritative admission and make it the case's ``target_states`` (client-supplied states are discarded)."""
    devices = list(case.affected_scope.get("devices", []))
    resolved = deps.admission.resolve(devices)
    for i, d in enumerate(devices):
        if i >= budget.max_devices and resolved[d].admitted:
            resolved[d] = DeviceAdmission(d, "BUDGET_EXCEEDED", resolved[d].platform, resolved[d].os_version, resolved[d].maintenance, resolved[d].source,
                                          f"more than {budget.max_devices} devices in one run")
    states = {d: resolved[d].state for d in devices}
    if states != dict(case.target_states):
        case.target_states = states
        case.save()
    repo.audit(actor, case, "ADMISSION_RESOLVED", decision=", ".join(f"{d}={s}" for d, s in sorted(states.items()))[:255], result="OK", now=now,
               rationale="target_states set from the authoritative inventory; client-supplied values discarded")
    return resolved


def run_case(actor: repo.Actor, case_id: str, deps: RuntimeDeps | None = None, *, runbook: str | None = None, run_key: str = "", budget: dict | RuntimeBudget | None = None,
             now: datetime | None = None, alarms: list[dict] | None = None, engine_config: eng.EngineConfig | None = None) -> dict[str, Any]:
    """Run Stage 1 for a case.  Idempotent per (case, run_key): a repeat (or restart) reuses finished collection runs, does not recontact finished
    devices, and the engine reloads recorded tests."""
    deps = deps or RuntimeDeps()
    case = repo.get_case(actor, case_id)
    rb = runbook or case.runbook
    if rb not in REGISTRY:
        raise ValueError(f"unknown or missing runbook {rb!r}; known: {sorted(REGISTRY)}")
    if case.runbook and case.runbook != rb:
        raise ValueError(f"case runbook is {case.runbook}; refusing to run {rb} on it")
    if case.state in m.TS_TERMINAL_CASE_STATES:
        raise ValueError(f"case {case.case_id} is closed ({case.state})")
    bud = budget if isinstance(budget, RuntimeBudget) else RuntimeBudget.clamp(budget)
    run_key = run_key or f"default-{case.case_id}"
    if len(run_key) > 64:
        raise ValueError("run_key too long (max 64)")
    now = now or deps.now()
    admissions = resolve_admission(actor, case, deps, bud, now)
    case = repo.get_case(actor, case.case_id)
    provider = CollectorProvider(actor, case, deps, admissions, bud, run_key)
    sources = deps.sources or cfg_ad.baseline_sources(actor, now=lambda: now)
    cfg = engine_config or eng.EngineConfig()
    cfg = eng.EngineConfig(**{**cfg.__dict__, "max_collection_runs": min(cfg.max_collection_runs, bud.max_collection_runs)})
    engine = eng.Engine(actor, case, rb, sources=sources, provider=provider, now=now, alarms=alarms, config=cfg)
    stages = engine.run()
    case = repo.get_case(actor, case.case_id)
    report = reporting.build_report(actor, case, now=now)
    return {"schema": RUN_SCHEMA, "runtime_version": RUNTIME_VERSION, "case_id": case.case_id, "runbook": rb, "run_key": run_key, "state": case.state,
            "budget": {f: getattr(bud, f) for f in RuntimeBudget.FIELDS},
            "admission": {d: a.as_dict() for d, a in admissions.items()},
            "collection": {"contacted": provider.report["contacted"], "resumed": provider.report["resumed"], "capability_gaps": provider.report["gaps"]},
            "diagnosis": stages["diagnosis"], "test_counts": _counts(stages["test"]["matrix"]), "handoff_gate": stages["handoff_gate"], "report": report}


def _counts(matrix: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in matrix:
        k = f"{r['status']}/{r['verdict']}"
        out[k] = out.get(k, 0) + 1
    return out


def received_keys(actor: repo.Actor, case) -> dict[str, list[str]]:
    """{device: sorted canonical keys with a usable (non-missing) observation} -- used for coverage reporting."""
    repo.get_case(actor, case.case_id)
    out: dict[str, set] = {}
    for o in m.TsObservation.objects.filter(case=case, is_missing_data=False):
        if actor.can_see_device(o.target):
            out.setdefault(o.target, set()).add(o.key.partition(KEY_SEP)[0])
    return {d: sorted(v) for d, v in out.items()}
