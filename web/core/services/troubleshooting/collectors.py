"""Bounded, read-only, admission-checked collectors for NMAS V2 troubleshooting (Stage 1 "Collect").

Independent of the case ORM: inputs are plain objects (``Target``, budgets, injected transports/sessions/readers), outputs are
versioned serializable dictionaries (a *collection bundle*: ``run`` + ``evidence`` + ``observations`` + ``missing``).  Normalization
lives in ``normalization.py``; real transports (existing health sessions, gateway, monitoring configs) live in ``adapters/``.

Safety properties (each asserted in ``test_troubleshooting_collectors``):

* **Admission first** -- ``check_admission``: only verified, non-withdrawn devices whose platform capability for the source type is
  SUPPORTED may be probed; anything else yields a REFUSED run with a missing-data record and *no transport call* (UT-002/UT-013).
* **Read-only by construction** -- CLI commands come only from ``COMMAND_CATALOG`` (addressed by key; parameters validated), are
  re-validated by ``validate_read_only`` and never contain a configuration/clear/reload/debug/active-probe verb; gNMI ``Set``,
  SNMP ``SET``, NETCONF ``edit-config``/``copy-config``/``delete-config``/``commit``/``lock`` and any other write are
  ``UNSUPPORTED_OPERATION`` -- the transport is never called (UT-053).
* **Bounded** -- ``Budget`` limits commands, wall-clock, bytes, records, retries and inter-command spacing; the stream buffer rejects
  (and *counts*) overflow rather than silently losing data (UT-022).
* **Honest failures** -- permission denial, timeout, budget exhaustion, unsupported command, parser unavailable: each is a missing-data
  record plus (where output exists) evidence with its status; none produces an observation (UT-024).
* **Provenance** -- every evidence dict carries transport, adapter + version, command/API, platform + OS version, times, a hash of the
  raw bytes as received, the redaction status and (for gateway transports) the gateway evidence sequence numbers.
* **No secrets** -- stored raw text is passed through ``redact_text``; credentials never enter dicts (sessions are opaque objects).
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

from . import normalization as nz
from .normalization import (
    EvidenceClass, Missing, canonical_interface, canonical_platform, iso, make_observation, missing_record, parse_version,
    redact_text, sha256_text, to_utc, utcnow)

BUNDLE_SCHEMA = "nmas.troubleshooting.collection-bundle/1"
RUN_SCHEMA = "nmas.troubleshooting.collection-run/1"
COLLECTOR_VERSION = "1.0.0"


class SourceType:
    GNMI_STREAM = "GNMI_STREAM"
    GNMI_GET = "GNMI_GET"
    SNMP_POLL = "SNMP_POLL"
    SYSLOG = "SYSLOG"
    NETFLOW = "NETFLOW"
    PCAP_METADATA = "PCAP_METADATA"
    CLI = "CLI"
    NETCONF = "NETCONF"
    CONFIG_SNAPSHOT = "CONFIG_SNAPSHOT"
    STATE_SNAPSHOT = "STATE_SNAPSHOT"
    NETBOX_INTENT = "NETBOX_INTENT"
    GOLDEN_CONFIG = "GOLDEN_CONFIG"
    TOPOLOGY_TELEMETRY = "TOPOLOGY_TELEMETRY"
    DNS_QUERY = "DNS_QUERY"
    ACTIVE_PROBE = "ACTIVE_PROBE"
    ALL = (GNMI_STREAM, GNMI_GET, SNMP_POLL, SYSLOG, NETFLOW, PCAP_METADATA, CLI, NETCONF, CONFIG_SNAPSHOT, STATE_SNAPSHOT, NETBOX_INTENT,
           GOLDEN_CONFIG, TOPOLOGY_TELEMETRY, DNS_QUERY, ACTIVE_PROBE)


# Spec 3.1: push vs poll, sampling period, freshness, overhead and backpressure for EVERY source (UT-023).
SOURCE_PROFILES: dict[str, dict] = {
    SourceType.GNMI_STREAM: {"mode": "push", "default_sampling_s": 20.0, "min_sampling_s": 5.0, "freshness_max_age_s": 60.0, "selectable": "stream",
                             "overhead": "One long-lived subscription per device; ~1 notification per path per sample interval (STREAM+SAMPLE 20 s repo default, "
                                         "monitoring/config/gnmi_paths.yml). Measured on-box CPU cost must be recorded per fixture; none is claimed here.",
                             "backpressure": "Bounded in-memory buffer; overflow is rejected AND counted (dropped_count) -> bundle flag DATA_LOSS; subscription "
                                             "interval below min_sampling_s is refused.",
                             "preferred_for": "fast transitions (link flap, adjacency change)"},
    SourceType.GNMI_GET: {"mode": "poll", "default_sampling_s": 30.0, "min_sampling_s": 5.0, "freshness_max_age_s": 120.0, "selectable": "poll",
                          "overhead": "One Get RPC per path set per poll; no standing state on the device.",
                          "backpressure": "Command/byte/time budget per run; min_interval_s spacing.", "preferred_for": "on-demand state check"},
    SourceType.SNMP_POLL: {"mode": "poll", "default_sampling_s": 60.0, "min_sampling_s": 10.0, "freshness_max_age_s": 180.0, "selectable": "poll",
                           "overhead": "IF-MIB walk (~10 columns x interface count) per poll; jittered to avoid synchronized polling.",
                           "backpressure": "Request budget + jitter + min_interval_s; counter wrap/reset/gap detection needs >=2 polls.",
                           "preferred_for": "error/discard counters, coarse utilization"},
    SourceType.SYSLOG: {"mode": "push", "default_sampling_s": None, "min_sampling_s": None, "freshness_max_age_s": 3600.0, "selectable": "stream",
                        "overhead": "Receiver-side only (existing rsyslog -> InfluxDB pipeline); no device polling.",
                        "backpressure": "Bounded batch size; overflow counted; duplicates collapsed with original refs preserved.",
                        "preferred_for": "event ordering, optics warnings, STP TCN, adjacency logs"},
    SourceType.NETFLOW: {"mode": "push", "default_sampling_s": None, "min_sampling_s": None, "freshness_max_age_s": 300.0, "selectable": "stream",
                         "overhead": "Exporter-side sampling; collector cost proportional to flow rate.",
                         "backpressure": "Service selector REQUIRED (no unscoped queries); record budget; sampling uncertainty retained.",
                         "preferred_for": "production-flow endpoints/ports/rates; sampling bias applies"},
    SourceType.PCAP_METADATA: {"mode": "on_demand", "default_sampling_s": None, "min_sampling_s": None, "freshness_max_age_s": 600.0, "selectable": "poll",
                               "overhead": "Capture itself runs elsewhere under explicit authorization; this module ingests metadata only.",
                               "backpressure": "Header-only snaplen, packet/byte/duration bounds, mandatory filter and authorization with expiry.",
                               "preferred_for": "handshake/retransmission/PMTUD/BPDU/DNS evidence"},
    SourceType.CLI: {"mode": "poll", "default_sampling_s": None, "min_sampling_s": 1.0, "freshness_max_age_s": 120.0, "selectable": "poll",
                     "overhead": "One session; show commands only; per-run command/time/byte budget.", "backpressure": "Budget + min_interval_s; bounded retry on timeout only.",
                     "preferred_for": "RIB/FIB, MAC/ARP/ND, STP, ACL/QoS detail"},
    SourceType.NETCONF: {"mode": "poll", "default_sampling_s": None, "min_sampling_s": 5.0, "freshness_max_age_s": 120.0, "selectable": "poll",
                         "overhead": "get/get-config with subtree filter only.", "backpressure": "Same as CLI.", "preferred_for": "structured OpenConfig state where supported"},
    SourceType.CONFIG_SNAPSHOT: {"mode": "on_demand", "default_sampling_s": None, "min_sampling_s": None, "freshness_max_age_s": 86400.0, "selectable": "poll",
                                 "overhead": "One read-only config retrieval.", "backpressure": "Byte budget.", "preferred_for": "change detection, golden comparison"},
    SourceType.STATE_SNAPSHOT: {"mode": "on_demand", "default_sampling_s": None, "min_sampling_s": None, "freshness_max_age_s": 300.0, "selectable": "poll",
                                "overhead": "Composed from CLI/telemetry reads.", "backpressure": "Same as CLI.", "preferred_for": "before/after comparison"},
    SourceType.NETBOX_INTENT: {"mode": "on_demand", "default_sampling_s": None, "min_sampling_s": None, "freshness_max_age_s": 86400.0, "selectable": "poll",
                               "overhead": "Read-only NetBox/NSOT queries via existing services.", "backpressure": "Provider-side; evidence_class='intent' (not proof of state).",
                               "preferred_for": "expected topology/addresses/VRFs"},
    SourceType.GOLDEN_CONFIG: {"mode": "on_demand", "default_sampling_s": None, "min_sampling_s": None, "freshness_max_age_s": 86400.0, "selectable": "poll",
                               "overhead": "Read-only golden bundle/page lookup.", "backpressure": "Provider-side.", "preferred_for": "intended config revision + URL + soak state"},
    SourceType.TOPOLOGY_TELEMETRY: {"mode": "poll", "default_sampling_s": 30.0, "min_sampling_s": 10.0, "freshness_max_age_s": 120.0, "selectable": "poll",
                                    "overhead": "One call to the existing topology service (InfluxDB-derived); no device contact.",
                                    "backpressure": "Single call; freshness taken from the service's own per-endpoint evidence_fresh.",
                                    "preferred_for": "monitored link endpoint state and node telemetry age"},
    SourceType.ACTIVE_PROBE: {"mode": "on_demand", "default_sampling_s": None, "min_sampling_s": None, "freshness_max_age_s": 120.0, "selectable": "poll",
                              "overhead": "A handful of TCP connects / one TTL-limited trace from the admitted source to an authorized destination, via an injected runner.",
                              "backpressure": "Per-case authorization with expiry, flow-tuple/destination/port scope, attempt/hop/byte/time caps, no retries (a retry is more traffic).",
                              "preferred_for": "TCP reachability from the real vantage; forward path location"},
    SourceType.DNS_QUERY: {"mode": "poll", "default_sampling_s": None, "min_sampling_s": 1.0, "freshness_max_age_s": 120.0, "selectable": "poll",
                           "overhead": "One typed request per (operation, name, server) through an injected authorized read-only runner; UDP with a single TCP fallback on truncation.",
                           "backpressure": "Request/byte/time budget, per-response size cap, answer-count cap, retries on timeout only; zone transfers / ANY are refused.",
                           "preferred_for": "authoritative vs recursive answers, SOA serial, cache TTL, UDP/TCP 53, delegation, DNSSEC (when the runner reports it)"},
}


def describe_sources() -> dict:
    """Serializable source catalogue (push/poll, sampling, freshness, overhead, backpressure) for documentation and planners."""
    return {"schema": "nmas.troubleshooting.source-catalog/1", "collector_version": COLLECTOR_VERSION,
            "sources": {k: dict(v) for k, v in SOURCE_PROFILES.items()}}


def plan_telemetry(*, gnmi: bool, snmp: bool, prefer: str = "auto") -> dict:
    """Streaming and polling are INDEPENDENTLY selectable (UT-023).  ``prefer``: ``stream`` | ``poll`` | ``both`` | ``auto`` (auto = stream
    when gNMI is available, else poll via SNMP).  Returns the selected source types with the reason; an unavailable choice is reported
    in ``unavailable`` rather than silently substituted."""
    selected, unavailable, reason = [], [], ""
    if prefer in ("stream", "both") or (prefer == "auto" and gnmi):
        (selected if gnmi else unavailable).append(SourceType.GNMI_STREAM)
    if prefer in ("poll", "both") or (prefer == "auto" and not gnmi):
        (selected if snmp else unavailable).append(SourceType.SNMP_POLL)
        if prefer in ("poll", "both") and gnmi:
            selected.append(SourceType.GNMI_GET)
    reason = {"stream": "streaming requested (fast transitions)", "poll": "polling requested", "both": "streaming and polling both requested",
              "auto": "auto: stream when gNMI is available, else poll"}.get(prefer, "unknown preference")
    if prefer not in ("stream", "poll", "both", "auto"):
        return {"selected": [], "unavailable": [], "reason": f"unknown preference {prefer!r}", "error": "INVALID_PREFERENCE"}
    return {"selected": selected, "unavailable": unavailable, "reason": reason}


# --------------------------------------------------------------------------------------------------------------------
# Budgets and backpressure
# --------------------------------------------------------------------------------------------------------------------
class BudgetExceeded(Exception):
    def __init__(self, which: str):
        super().__init__(which)
        self.which = which


@dataclass(frozen=True)
class Budget:
    max_commands: int = 20
    max_seconds: float = 60.0
    max_bytes: int = 2_000_000
    max_records: int = 10_000
    max_retries: int = 1              # extra attempts per command, on timeout/transient transport errors ONLY
    min_interval_s: float = 0.0       # rate bound: minimum spacing between consecutive device requests
    backoff_s: float = 0.5
    per_command_timeout_s: float = 20.0

    def as_dict(self) -> dict:
        return dict(self.__dict__)


class BudgetTracker:
    def __init__(self, budget: Budget, *, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self.budget, self._clock, self._sleep = budget, clock, sleep
        self.started = clock()
        self.commands = self.bytes = self.records = self.retries = 0
        self._last_request: float | None = None
        self.throttled_s = 0.0

    def elapsed(self) -> float:
        return self._clock() - self.started

    def before_request(self) -> None:
        if self.commands >= self.budget.max_commands:
            raise BudgetExceeded("COMMANDS")
        if self.elapsed() >= self.budget.max_seconds:
            raise BudgetExceeded("TIME")
        if self.bytes >= self.budget.max_bytes:
            raise BudgetExceeded("BYTES")
        if self._last_request is not None and self.budget.min_interval_s > 0:
            wait = self.budget.min_interval_s - (self._clock() - self._last_request)
            if wait > 0:
                if self.elapsed() + wait >= self.budget.max_seconds:
                    raise BudgetExceeded("TIME")
                self._sleep(wait)
                self.throttled_s += wait
        self._last_request = self._clock()
        self.commands += 1

    def add_bytes(self, n: int) -> None:
        self.bytes += n
        if self.bytes > self.budget.max_bytes:
            raise BudgetExceeded("BYTES")

    def add_records(self, n: int = 1) -> None:
        self.records += n
        if self.records > self.budget.max_records:
            raise BudgetExceeded("RECORDS")

    def used(self) -> dict:
        return {"commands": self.commands, "seconds": round(self.elapsed(), 3), "bytes": self.bytes, "records": self.records,
                "retries": self.retries, "throttled_s": round(self.throttled_s, 3)}


class BoundedBuffer:
    """Backpressure for push sources: fixed capacity, overflow is REJECTED and COUNTED (never silent)."""

    def __init__(self, capacity: int):
        self.capacity, self.items, self.dropped = capacity, [], 0

    def offer(self, item) -> bool:
        if len(self.items) >= self.capacity:
            self.dropped += 1
            return False
        self.items.append(item)
        return True


# --------------------------------------------------------------------------------------------------------------------
# Targets, admission, capability
# --------------------------------------------------------------------------------------------------------------------
ADMITTED_STATES = frozenset({"ADMITTED", "ACTIVE", "VERIFIED", "MANAGED", "IN_SERVICE", "OPERATIONAL"})
BLOCKED_STATES = frozenset({"WITHDRAWN", "DECOMMISSIONED", "DECOMMISSION", "RETIRED", "UNVERIFIED", "PENDING", "REJECTED", "QUARANTINED"})


@dataclass(frozen=True)
class Target:
    """A device as the NMAS inventory/lifecycle sees it.  No credentials: transports are injected and opaque."""

    device: str
    platform: str
    os_version: str = ""
    lifecycle_state: str = "ADMITTED"
    verified: bool = True
    withdrawn: bool = False
    maintenance: bool = False
    capabilities: dict = field(default_factory=dict)   # {source_type: "SUPPORTED"|...}; consulted only when no capability_probe is given

    @property
    def canonical_platform(self) -> str:
        return canonical_platform(self.platform)


@dataclass(frozen=True)
class Admission:
    ok: bool
    code: str = "ADMITTED"
    detail: str = ""
    flags: tuple = ()


CapabilityProbe = Callable[[str, str], dict]    # (canonical platform, source_type) -> {"status": "SUPPORTED"|..., "evidence": "...", "transport": "..."}


def check_admission(target: Target, source_type: str, *, operation: str = "read", capability_probe: CapabilityProbe | None = None,
                    authorized_sources: Iterable[str] | None = None) -> Admission:
    """Capability/admission gate evaluated BEFORE any transport is touched.  Fail closed: an unknown capability is not SUPPORTED."""
    if operation != "read":
        return Admission(False, Missing.UNSUPPORTED_OPERATION, f"operation {operation!r} is not permitted: collection is read-only")
    if source_type not in SourceType.ALL:
        return Admission(False, Missing.UNSUPPORTED_OPERATION, f"unknown source type {source_type!r}")
    state = str(target.lifecycle_state or "").upper()
    if target.withdrawn or state in BLOCKED_STATES:
        return Admission(False, Missing.NOT_ADMITTED, f"device lifecycle state {state or 'UNKNOWN'} / withdrawn={target.withdrawn}: not probed")
    if not target.verified or (state and state not in ADMITTED_STATES):
        return Admission(False, Missing.NOT_ADMITTED, f"device is not verified/admitted (state {state or 'UNKNOWN'}): not probed")
    if authorized_sources is not None and source_type not in set(authorized_sources):
        return Admission(False, Missing.NOT_ADMITTED, f"source type {source_type} not authorized for this case")
    if capability_probe is not None:
        cap = capability_probe(target.canonical_platform, source_type) or {}
        status = str(cap.get("status", "UNKNOWN")).upper()
    else:
        status = str(target.capabilities.get(source_type, "UNKNOWN")).upper()
    if status != "SUPPORTED":
        return Admission(False, Missing.UNSUPPORTED_PLATFORM,
                         f"platform {target.canonical_platform or '?'} capability for {source_type} is {status}: not attempted")
    return Admission(True, flags=("MAINTENANCE_MODE",) if target.maintenance else ())


# --------------------------------------------------------------------------------------------------------------------
# CLI command catalogue and read-only validation
# --------------------------------------------------------------------------------------------------------------------
class CommandNotAllowed(Exception):
    pass


@dataclass(frozen=True)
class CommandSpec:
    key: str
    platform: str
    command: Any                          # str (network CLI) | tuple argv (Linux/FRR; no shell)
    parser_id: str | None = None          # normalization parser id; None => evidence retained, no parser (recorded as PARSER_UNAVAILABLE)
    domains: tuple = ()
    params: tuple = ()
    min_version: tuple = ()
    kind: str = "state"                   # state | config | version
    description: str = ""


_IFACE_PARAM = re.compile(r"^[A-Za-z][A-Za-z0-9\-]{0,24}[0-9/.:]{0,16}$")
_PARAM_VALIDATORS = {"interface": _IFACE_PARAM}


def _spec(*a, **k) -> CommandSpec:
    return CommandSpec(*a, **k)


_CEOS = [
    _spec("version", "ceos", "show version | json", None, ("identity",), kind="version", description="Image and uptime"),
    _spec("interfaces", "ceos", "show interfaces | json", "interfaces.state", ("link_flap", "physical", "mtu", "reachability"), description="All interfaces: state, MTU, counters"),
    _spec("interface", "ceos", "show interfaces {interface} | json", "interfaces.state", ("link_flap", "physical", "mtu"), ("interface",), description="One interface"),
    _spec("ospf_neighbors", "ceos", "show ip ospf neighbor | json", "ospf.neighbors", ("routing",), description="OSPFv2 neighbors"),
    _spec("ospf3_neighbors", "ceos", "show ipv6 ospf neighbor | json", "ospf.neighbors", ("routing",), description="OSPFv3 neighbors"),
    _spec("bgp_summary", "ceos", "show ip bgp summary | json", "bgp.summary", ("routing",), description="BGP IPv4 peers"),
    _spec("bgp6_summary", "ceos", "show ipv6 bgp summary | json", "bgp.summary", ("routing",), description="BGP IPv6 peers"),
    _spec("ip_route", "ceos", "show ip route | json", "route.table", ("reachability", "routing"), description="IPv4 RIB (parser eos-json-1.0, EOS 4.28 <= v < 5.0; never a FIB)"),
    _spec("ipv6_route", "ceos", "show ipv6 route | json", "route.table", ("reachability", "routing"), description="IPv6 RIB (parser eos-json-1.0; never a FIB)"),
    _spec("ip_route_summary", "ceos", "show ip route summary | json", None, ("routing",),
          description="IPv4 route counts per protocol incl. OSPF externals and RIP (redistribution evidence; routing.ceos_summary_counts)"),
    _spec("ipv6_route_summary", "ceos", "show ipv6 route summary | json", None, ("routing",),
          description="IPv6 route counts per protocol (routing.ceos_summary_counts)"),
    _spec("arp", "ceos", "show ip arp | json", "neighbor.table", ("reachability",), description="ARP cache (parser eos-json-1.0)"),
    _spec("ipv6_neighbors", "ceos", "show ipv6 neighbors | json", "neighbor.table", ("reachability",), description="IPv6 ND cache (parser eos-json-1.0)"),
    _spec("mac_table", "ceos", "show mac address-table | json", "mac.table", ("stp", "reachability", "l2"), description="MAC table (version-gated parser eos-json-1.0, EOS 4.28 <= v < 5.0; movement needs history)"),
    _spec("switchport", "ceos", "show interfaces switchport | json", "l2.port", ("l2",), description="Port mode / access VLAN / allowed VLANs (version-gated parser eos-json-1.0, EOS 4.28 <= v < 5.0)"),
    _spec("acl_rules", "ceos", "show ip access-lists | json", "acl.rules", ("acl",), description="IPv4 ACL rules + per-rule counters (version-gated parser eos-json-1.0, EOS 4.28 <= v < 5.0; attachment is NOT in this output)"),
    _spec("acl_attach", "ceos", "show ip access-lists summary | json", "acl.attachment", ("acl",), description="IPv4 ACL interface attachments and direction (version-gated parser eos-json-1.0, EOS 4.28 <= v < 5.0)"),
    _spec("spanning_tree", "ceos", "show spanning-tree | json", "stp.state", ("stp",), description="STP state: root/port roles/topology changes (version-gated parser eos-json-1.0, EOS 4.28 <= v < 5.0)"),
    _spec("interface_transceiver", "ceos", "show interfaces {interface} transceiver", None, ("physical",), ("interface",), description="Optics DOM (platform may not support)"),
    _spec("running_config", "ceos", "show running-config", None, ("snapshot",), kind="config", description="Running configuration snapshot"),
]
_IOSXE = [
    _spec("version", "iosxe", "show version", None, ("identity",), kind="version", description="Image and uptime"),
    _spec("interfaces", "iosxe", "show interfaces", "interfaces.state", ("link_flap", "physical", "mtu", "reachability"), description="All interfaces"),
    _spec("interface", "iosxe", "show interfaces {interface}", "interfaces.state", ("link_flap", "physical", "mtu"), ("interface",), description="One interface"),
    _spec("ospf_neighbors", "iosxe", "show ip ospf neighbor", "ospf.neighbors", ("routing",), description="OSPFv2 neighbors"),
    _spec("ip_route", "iosxe", "show ip route", None, ("reachability", "routing"), description="IPv4 RIB (evidence only)"),
    _spec("arp", "iosxe", "show ip arp", None, ("reachability",), description="ARP (evidence only)"),
    _spec("mac_table", "iosxe", "show mac address-table", None, ("stp", "reachability"), description="MAC table (evidence only)"),
    _spec("spanning_tree", "iosxe", "show spanning-tree", None, ("stp",), description="STP (evidence only)"),
    _spec("interface_transceiver", "iosxe", "show interfaces {interface} transceiver detail", None, ("physical",), ("interface",), description="Optics DOM"),
    _spec("running_config", "iosxe", "show running-config", None, ("snapshot",), kind="config", description="Running configuration snapshot"),
]
_LINUX = [
    _spec("version", "linux", ("vtysh", "-c", "show version"), None, ("identity",), kind="version", description="FRR version"),
    _spec("addr", "linux", ("ip", "-j", "addr", "show"), "interfaces.state", ("link_flap", "mtu", "reachability"), description="Interfaces + addresses"),
    _spec("link_stats", "linux", ("ip", "-j", "-s", "link", "show"), None, ("physical",), description="Link counters (evidence only)"),
    _spec("route4", "linux", ("ip", "-j", "-4", "route", "show"), "route.table", ("reachability", "routing"), description="IPv4 kernel routing table (RIB view; not an independently validated FIB)"),
    _spec("route6", "linux", ("ip", "-j", "-6", "route", "show"), "route.table", ("reachability", "routing"), description="IPv6 kernel routing table (RIB view; not an independently validated FIB)"),
    _spec("neigh", "linux", ("ip", "-j", "neigh", "show"), "neighbor.table", ("reachability",), description="ARP/ND cache (both families)"),
    _spec("ospf_neighbors", "linux", ("vtysh", "-c", "show ip ospf neighbor json"), "ospf.neighbors", ("routing",), description="FRR OSPFv2 neighbors"),
    _spec("ospf6_neighbors", "linux", ("vtysh", "-c", "show ipv6 ospf6 neighbor json"), None, ("routing",), description="FRR OSPFv3 neighbors (evidence only)"),
    _spec("bgp_summary", "linux", ("vtysh", "-c", "show bgp summary json"), "bgp.summary", ("routing",), description="FRR BGP summary"),
    _spec("frr_route4", "linux", ("vtysh", "-c", "show ip route json"), None, ("routing", "reachability"),
          description="FRR IPv4 RIB: protocol, selected/installed flags, next hops (evidence; parsed by routing.py)"),
    _spec("frr_route6", "linux", ("vtysh", "-c", "show ipv6 route json"), None, ("routing", "reachability"),
          description="FRR IPv6 RIB (evidence; parsed by routing.py)"),
    _spec("ospf_interfaces", "linux", ("vtysh", "-c", "show ip ospf interface json"), None, ("routing",),
          description="FRR OSPFv2 interfaces: area, network type, timers (evidence only)"),
    _spec("frr_config", "linux", ("vtysh", "-c", "show running-config"), None, ("snapshot",), kind="config", description="FRR running config"),
]
FORWARDING_V4_KEYS = frozenset({"ip_route", "route4", "arp"})
FORWARDING_V6_KEYS = frozenset({"ipv6_route", "route6", "ipv6_neighbors"})
COMMAND_CATALOG: dict[str, dict[str, CommandSpec]] = {p: {s.key: s for s in specs} for p, specs in (("ceos", _CEOS), ("iosxe", _IOSXE), ("linux", _LINUX))}

# Verbs that make a network CLI command non-read-only or an active probe (active probes are outside this module's remit: HC17/HC21 tests
# own their own authorized, rate-bounded probe tooling).
_FORBIDDEN_WORDS = frozenset({
    "configure", "conf", "config-session", "commit", "write", "copy", "clear", "reload", "reboot", "restart", "shutdown", "delete", "erase", "format",
    "debug", "undebug", "terminal", "enable", "disable", "ping", "traceroute", "trace", "telnet", "ssh", "bash", "python", "tclsh", "guestshell", "run",
    "no", "default", "set", "add", "del", "flush", "replace", "install", "upgrade", "boot", "test", "send", "monitor", "tcpdump",
})
_CLI_ALLOWED = re.compile(r"^show [A-Za-z0-9 .:/\-]+?( \| json)?$")
_LINUX_FIXED = {tuple(s.command) for s in _LINUX if isinstance(s.command, tuple)}
_VTYSH_SHOW = re.compile(r"^show [a-z0-9 \-]+$")


def validate_read_only(platform: str, rendered) -> None:
    """Raise ``CommandNotAllowed`` unless ``rendered`` is a read-only command for the platform.  Defence in depth: it is applied AFTER
    catalogue lookup and parameter rendering, to the final string/argv."""
    plat = canonical_platform(platform)
    if plat == "linux":
        argv = tuple(rendered) if isinstance(rendered, (tuple, list)) else None
        if argv is None:
            raise CommandNotAllowed("Linux/FRR commands must be argv tuples (no shell)")
        if argv in _LINUX_FIXED:
            return
        if len(argv) == 3 and argv[0] == "vtysh" and argv[1] == "-c" and _VTYSH_SHOW.match(argv[2]) and not (set(argv[2].split()) & _FORBIDDEN_WORDS):
            return
        raise CommandNotAllowed(f"argv not in the Linux/FRR read-only set: {argv!r}")
    if plat not in ("ceos", "iosxe") or not isinstance(rendered, str):
        raise CommandNotAllowed(f"no read-only command policy for platform {plat!r}")
    if not _CLI_ALLOWED.match(rendered):
        raise CommandNotAllowed(f"not a plain show command: {rendered!r}")
    if " | json" in rendered and plat != "ceos":
        raise CommandNotAllowed("JSON output pipe exists on EOS only")
    words = set(re.split(r"[\s|]+", rendered.lower().replace(" | json", "")))
    bad = words & _FORBIDDEN_WORDS
    if bad:
        raise CommandNotAllowed(f"forbidden verb(s) {sorted(bad)} in {rendered!r}")


def commands_for(platform: str, os_version: str = "", domains: Iterable[str] | None = None, *, include_config: bool = False) -> list[CommandSpec]:
    """UT-013: the supported, safe, read-only commands for the platform/version (optionally filtered by troubleshooting domain)."""
    plat = canonical_platform(platform)
    version = parse_version(os_version)
    wanted = set(domains) if domains else None
    out = []
    for spec in COMMAND_CATALOG.get(plat, {}).values():
        if spec.kind == "config" and not include_config:
            continue
        if spec.min_version and version and version < spec.min_version:
            continue
        if wanted and not (wanted & set(spec.domains)) and spec.kind != "version":
            continue
        out.append(spec)
    return out


def render_command(spec: CommandSpec, params: dict | None = None):
    params = params or {}
    if set(params) - set(spec.params):
        raise CommandNotAllowed(f"unexpected parameter(s) {sorted(set(params) - set(spec.params))} for {spec.key}")
    values = {}
    for name in spec.params:
        value = str(params.get(name, ""))
        pattern = _PARAM_VALIDATORS.get(name)
        if not value or pattern is None or not pattern.match(value):
            raise CommandNotAllowed(f"parameter {name!r} missing or invalid for {spec.key}")
        values[name] = value
    rendered = spec.command.format(**values) if isinstance(spec.command, str) else spec.command
    validate_read_only(spec.platform, rendered)
    return rendered


_DENIED = re.compile(r"(authorization (?:denied|failed)|permission denied|access denied|not authori[sz]ed|insufficient privilege|privilege level|%\s*command authorization)", re.I)
_UNSUPPORTED = re.compile(r"(% ?invalid input|invalid command|unrecognized command|% ?unknown command|command not found|unavailable command|"
                          r"not supported|not available|unsupported|% ?incomplete command|% ?ambiguous command|% ?bad ip address|unknown command)", re.I)


def classify_output(text: str) -> tuple[str, str]:
    """(status, detail): ``OK`` | ``PERMISSION_DENIED`` | ``UNSUPPORTED`` | ``DEVICE_NOTE`` (JSON ``errors`` reported by the device)."""
    head = text.strip()[:400]
    if _DENIED.search(head):
        return "PERMISSION_DENIED", head.splitlines()[0][:160] if head else ""
    if head.startswith("{") and '"errors"' in head:
        try:
            errs = json.loads(text).get("errors")
            if errs:
                return "DEVICE_NOTE", "; ".join(map(str, errs))[:200]
        except ValueError:
            pass
    short = text.strip()
    if _UNSUPPORTED.search(short[:600]) and len(short) < 600:
        return "UNSUPPORTED", short.splitlines()[0][:160]
    return "OK", ""


class TransportError(Exception):
    """Transient transport failure (retried within the budget).  ``code`` is sanitized; never carries credentials."""

    def __init__(self, code: str = "TRANSPORT_ERROR", transient: bool = True):
        super().__init__(code)
        self.code, self.transient = code, transient


class PermissionDenied(Exception):
    pass


# --------------------------------------------------------------------------------------------------------------------
# Raw stores, evidence, bundle assembly
# --------------------------------------------------------------------------------------------------------------------
class InMemoryRawStore:
    """Replay store: ``put`` keeps the REDACTED raw text keyed by the as-received hash.  Production callers inject a secured store."""

    def __init__(self):
        self.items: dict[str, str] = {}

    def put(self, raw_hash: str, redacted_text: str) -> str:
        self.items[raw_hash] = redacted_text
        return f"mem:{raw_hash}"


def build_evidence(*, seq: int, source_type: str, transport: str, adapter: str, device: str, platform: str, os_version: str, command_or_api: str,
                   raw: str | None, started_at: datetime, finished_at: datetime, status: str, status_detail: str = "", store=None,
                   extra: dict | None = None, coverage: dict | None = None, gateway: dict | None = None, evidence_class: str = EvidenceClass.OPERATIONAL,
                   freshness_max_age_s: float | None = None, parser: dict | None = None) -> dict:
    """The evidence contract ``nmas.troubleshooting.evidence/1``."""
    raw_hash = sha256_text(raw) if raw is not None else None
    redacted, redactions = redact_text(raw) if raw is not None else ("", 0)
    pointer = store.put(raw_hash, redacted) if (store is not None and raw_hash) else None
    ident = nz.sha256_json([device, source_type, command_or_api, iso(started_at), raw_hash, seq])[7:23]
    return {
        "schema": nz.EVIDENCE_SCHEMA, "evidence_id": f"ev-{ident}", "sequence": seq, "source_type": source_type, "transport": transport, "adapter": adapter,
        "adapter_version": COLLECTOR_VERSION, "device": device, "platform": canonical_platform(platform), "os_version": os_version,
        "command_or_api": command_or_api, "started_at": iso(started_at), "collected_at": iso(finished_at), "duration_s": round((finished_at - started_at).total_seconds(), 3),
        "status": status, "status_detail": status_detail, "evidence_class": evidence_class,
        "freshness_max_age_s": freshness_max_age_s or SOURCE_PROFILES.get(source_type, {}).get("freshness_max_age_s", 300.0),
        "raw_ref": {"hash": raw_hash, "bytes": len(raw.encode("utf-8", "replace")) if raw is not None else 0, "stored_hash": sha256_text(redacted) if raw is not None else None,
                    "pointer": pointer, "operator_view": "reference-only"},
        "redaction": {"status": ("REDACTED" if redactions else "CHECKED_NO_SECRETS") if raw is not None else "NOT_APPLICABLE", "redactions": redactions},
        "parser": parser or None, "coverage": coverage or None, "gateway": gateway or None, "extra": extra or None,
    }


class _Run:
    """Mutable builder for one collection run; ``bundle()`` produces the serializable result."""

    def __init__(self, collector: str, source_type: str, target: Target, *, tracker: BudgetTracker, clock_now: Callable[[], datetime],
                 transport: str, adapter: str, admission: Admission | None = None):
        self.collector, self.source_type, self.target = collector, source_type, target
        self.tracker, self.now = tracker, clock_now
        self.transport, self.adapter = transport, adapter
        self.started = clock_now()
        self.evidence: list[dict] = []
        self.observations: list[dict] = []
        self.missing: list[dict] = []
        self.commands: list[str] = []
        self.requested = 0
        self.flags: list[str] = list(admission.flags) if admission else []
        self.seq = 0
        self.gateway: dict | None = None
        self.refused: Admission | None = None

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def bundle(self, *, extra: dict | None = None) -> dict:
        finished = self.now()
        collected = len([e for e in self.evidence if e["status"] in ("OK", "DEVICE_NOTE")])
        if self.refused is not None:
            status = "REFUSED"
        elif not self.missing and collected:
            status = "COMPLETE"
        elif collected or self.observations:
            status = "PARTIAL"
        else:
            status = "FAILED"
        by_reason: dict[str, int] = {}
        for m in self.missing:
            by_reason[m["reason"]] = by_reason.get(m["reason"], 0) + 1
        run = {
            "schema": RUN_SCHEMA, "run_id": "run-" + nz.sha256_json([self.target.device, self.source_type, iso(self.started)])[7:19], "stage": "collect", "stage_order": 1,
            "collector": self.collector, "collector_version": COLLECTOR_VERSION, "adapter": self.adapter, "transport": self.transport, "source_type": self.source_type,
            "device": self.target.device, "platform": self.target.canonical_platform, "os_version": self.target.os_version, "privileges": "read-only",
            "command_or_api": self.commands, "started_at": iso(self.started), "finished_at": iso(finished), "status": status,
            "retries": self.tracker.retries, "timeout_s": self.tracker.budget.per_command_timeout_s,
            "rate_budget": {"min_interval_s": self.tracker.budget.min_interval_s, "max_commands": self.tracker.budget.max_commands},
            "budget": {"limits": self.tracker.budget.as_dict(), "used": self.tracker.used()},
            "evidence_ids": [e["evidence_id"] for e in self.evidence], "flags": self.flags, "gateway": self.gateway,
            "admission": ({"ok": False, "code": self.refused.code, "detail": self.refused.detail} if self.refused else {"ok": True}),
        }
        if extra:
            run.update(extra)
        return {"schema": BUNDLE_SCHEMA, "run": run, "evidence": self.evidence, "observations": self.observations, "missing": self.missing,
                "coverage": {"requested": self.requested, "collected": collected, "missing_by_reason": by_reason, "observations": len(self.observations)}}


def _refuse(run: _Run, admission: Admission, what: str) -> dict:
    run.refused = admission
    run.requested = max(run.requested, 1)
    run.missing.append(missing_record(admission.code, source_type=run.source_type, device=run.target.device, detail=admission.detail, command=what, observed_at=run.now()))
    return run.bundle()


def merge_bundles(bundles: Iterable[dict]) -> dict:
    """Combine bundles (kept as ordered ``runs``) into one collection result for the correlator."""
    bundles = list(bundles)
    cov: dict[str, int] = {}
    for b in bundles:
        for k, v in b["coverage"]["missing_by_reason"].items():
            cov[k] = cov.get(k, 0) + v
    return {"schema": BUNDLE_SCHEMA + "-set", "runs": [b["run"] for b in bundles], "evidence": [e for b in bundles for e in b["evidence"]],
            "observations": [o for b in bundles for o in b["observations"]], "missing": [m for b in bundles for m in b["missing"]],
            "coverage": {"requested": sum(b["coverage"]["requested"] for b in bundles), "collected": sum(b["coverage"]["collected"] for b in bundles), "missing_by_reason": cov}}


# --------------------------------------------------------------------------------------------------------------------
# Collector base
# --------------------------------------------------------------------------------------------------------------------
class _BaseCollector:
    source_type = SourceType.CLI
    name = "base"
    READ_OPERATIONS: frozenset = frozenset()

    def __init__(self, *, budget: Budget | None = None, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 now: Callable[[], datetime] = utcnow, raw_store=None, capability_probe: CapabilityProbe | None = None,
                 authorized_sources: Iterable[str] | None = None, adapter: str = "injected"):
        self.budget = budget or Budget()
        self._clock, self._sleep, self._now = clock, sleep, now
        self.raw_store = raw_store
        self.capability_probe, self.authorized_sources = capability_probe, authorized_sources
        self.adapter = adapter

    def _run(self, target: Target, transport: str, operation: str = "read") -> tuple[_Run, Admission]:
        admission = check_admission(target, self.source_type, operation=operation, capability_probe=self.capability_probe,
                                    authorized_sources=self.authorized_sources)
        tracker = BudgetTracker(self.budget, clock=self._clock, sleep=self._sleep)
        return _Run(self.name, self.source_type, target, tracker=tracker, clock_now=self._now, transport=transport, adapter=self.adapter, admission=admission), admission

    def refuse_operation(self, target: Target, operation: str, detail: str = "") -> dict:
        """Any non-read operation (gNMI Set, SNMP SET, NETCONF edit-config, ...) is refused WITHOUT touching a transport."""
        run, _ = self._run(target, "none", operation="write")
        run.commands.append(f"REFUSED:{operation}")
        return _refuse(run, Admission(False, Missing.UNSUPPORTED_OPERATION, detail or f"{operation}: collection is read-only; no write operation exists in this module"), operation)

    def _fail(self, run: _Run, reason: str, detail: str, command: str) -> None:
        run.missing.append(missing_record(reason, source_type=run.source_type, device=run.target.device, detail=detail, command=command, observed_at=run.now()))


# --------------------------------------------------------------------------------------------------------------------
# CLI collector
# --------------------------------------------------------------------------------------------------------------------
_VERSION_RE = (re.compile(r"Software image version:\s*(\S+)"), re.compile(r"Version\s+(\d+\.\d+[\w.()]*)"), re.compile(r"FRRouting\s+(\d+\.\d+(?:\.\d+)?)"),
               re.compile(r"\"version\":\s*\"([^\"]+)\""))


def extract_version(text: str) -> str:
    for rx in _VERSION_RE:
        m = rx.search(text or "")
        if m:
            return m.group(1)
    return ""


class CliCollector(_BaseCollector):
    """Read-only CLI collection.  ``transport`` is any object with ``execute(rendered_command) -> str`` (see ``adapters``).

    ``stp_context`` (optional, ``adapters.stp.StpContext``) carries the previous-sample history and the VLANs a single-instance STP mode serves."""

    stp_context = None
    acl_context = None         # adapters.acl.AclContext (counter history); None => counter deltas are UNKNOWN
    l2_context = None          # adapters.l2.L2Context (MAC history); None => movement is UNKNOWN

    source_type = SourceType.CLI
    name = "cli"
    READ_OPERATIONS = frozenset({"show"})

    def collect(self, target: Target, keys: Iterable[str], transport, *, params: dict | None = None, clock_model: dict | None = None,
                transport_name: str = "cli") -> dict:
        keys = list(keys)
        run, admission = self._run(target, transport_name)
        run.requested = len(keys)
        if not admission.ok:
            run.commands = [f"{k}" for k in keys]
            return _refuse(run, admission, ",".join(keys))
        provenance = getattr(transport, "provenance", None)
        exhausted: str | None = None
        for key in keys:
            spec = COMMAND_CATALOG.get(target.canonical_platform, {}).get(key)
            if exhausted:
                self._fail(run, Missing.BUDGET_EXCEEDED, f"budget exhausted ({exhausted}) before {key}", key)
                continue
            if spec is None:
                self._fail(run, Missing.COMMAND_NOT_ALLOWED if key not in {k for p in COMMAND_CATALOG.values() for k in p} else Missing.UNSUPPORTED_OPERATION,
                           f"no catalogued read-only command {key!r} for platform {target.canonical_platform}", key)
                continue
            if spec.parser_id in ("stp.state", "route.table", "neighbor.table", "mac.table", "l2.port", "acl.rules", "acl.attachment"):      # version-gated parsers: refuse BEFORE contacting the device
                try:
                    nz.select_parser(spec.parser_id, target.platform, target.os_version)
                except nz.ParserSelectionError as exc:
                    self._fail(run, Missing.PARSER_UNAVAILABLE, str(exc), spec.command)
                    continue
            version = parse_version(target.os_version)
            if spec.min_version and version and version < spec.min_version:
                self._fail(run, Missing.UNSUPPORTED_PLATFORM, f"{key} needs OS >= {'.'.join(map(str, spec.min_version))}", key)
                continue
            try:
                rendered = render_command(spec, (params or {}).get(key) or (params if spec.params else None))
            except CommandNotAllowed as exc:
                self._fail(run, Missing.COMMAND_NOT_ALLOWED, str(exc), key)
                continue
            shown = rendered if isinstance(rendered, str) else " ".join(rendered)
            run.commands.append(shown)
            try:
                operation_params = (params or {}).get(key) or (params if spec.params else None) or {}
                raw, started, finished, attempts_note = self._execute(run, transport, rendered, operation_id=key,
                                                                       operation_params=operation_params)
            except BudgetExceeded as exc:
                exhausted = exc.which
                self._fail(run, Missing.BUDGET_EXCEEDED, f"{exc.which} budget exhausted before/while running {key}", shown)
                continue
            except PermissionDenied:
                self._fail(run, Missing.PERMISSION_DENIED, "transport reported permission denied", shown)
                continue
            except TimeoutError:
                self._fail(run, Missing.TIMEOUT, f"timeout after {self.budget.max_retries + 1} attempt(s)", shown)
                continue
            except TransportError as exc:
                self._fail(run, Missing.TRANSPORT_ERROR, exc.code, shown)
                continue
            if len(raw.encode("utf-8", "replace")) > self.budget.max_bytes:
                self._fail(run, Missing.OUTPUT_TOO_LARGE, f"output exceeds {self.budget.max_bytes} bytes; discarded", shown)
                continue
            status, detail = classify_output(raw)
            seq = run.next_seq()
            gw = provenance() if callable(provenance) else None
            if gw:
                run.gateway = gw
            evidence = build_evidence(seq=seq, source_type=SourceType.CLI if spec.kind != "config" else SourceType.CONFIG_SNAPSHOT, transport=transport_name,
                                      adapter=self.adapter, device=target.device, platform=target.platform, os_version=target.os_version, command_or_api=shown,
                                      raw=raw, started_at=started, finished_at=finished, status=status, status_detail=detail, store=self.raw_store, gateway=gw,
                                      extra={"attempts": attempts_note})
            run.evidence.append(evidence)
            if status == "PERMISSION_DENIED":
                self._fail(run, Missing.PERMISSION_DENIED, detail, shown)
                continue
            if status == "UNSUPPORTED":
                self._fail(run, Missing.UNSUPPORTED_OPERATION, detail or "device rejected the command", shown)
                continue
            if spec.kind == "version":
                found = extract_version(raw)
                if found and not target.os_version:
                    run.flags.append(f"OS_VERSION_DISCOVERED:{found}")
                continue
            self._normalize(run, spec, raw, evidence, target, clock_model, status, detail)
        return run.bundle()

    def _execute(self, run: _Run, transport, rendered, *, operation_id: str, operation_params: dict):
        attempts = 0
        while True:
            run.tracker.before_request()
            attempts += 1
            started = run.now()
            try:
                typed = getattr(transport, "execute_operation", None)
                raw = typed(operation_id, dict(operation_params), rendered) if callable(typed) else transport.execute(rendered)
                run.tracker.add_bytes(len((raw or "").encode("utf-8", "replace")))
                return raw or "", started, run.now(), attempts
            except (TimeoutError, TransportError) as exc:
                transient = isinstance(exc, TimeoutError) or exc.transient
                if not transient or attempts > self.budget.max_retries:
                    raise
                run.tracker.retries += 1
                self._sleep(self.budget.backoff_s * attempts)

    def _normalize(self, run: _Run, spec: CommandSpec, raw: str, evidence: dict, target: Target, clock_model, status: str, detail: str) -> None:
        if spec.kind == "config":
            res = nz.normalize_snapshot("running-config", raw, device=target.device, evidence=evidence, now=run.now())
            run.observations.extend(res["observations"])
            return
        if status == "DEVICE_NOTE":
            self._fail(run, Missing.EMPTY, f"device reported: {detail}", evidence["command_or_api"])
            return
        if not raw.strip():
            self._fail(run, Missing.EMPTY, "device returned empty output (feature/protocol not running or not supported on this platform); absence is NOT evidence of absence",
                       evidence["command_or_api"])
            return
        if spec.parser_id is None:
            self._fail(run, Missing.PARSER_UNAVAILABLE, f"no validated parser for {spec.key} on {target.canonical_platform}; evidence retained unparsed",
                       evidence["command_or_api"])
            return
        if spec.parser_id == "interfaces.state":
            check = nz.ios_raw_text_check if target.canonical_platform == "iosxe" else None
            res = nz.normalize_interfaces(raw, parser_id=spec.parser_id, platform=target.platform, os_version=target.os_version, device=target.device,
                                          evidence=evidence, now=run.now(), clock=clock_model, raw_text_check=check)
        elif spec.parser_id == "stp.state":
            ctx = getattr(self, "stp_context", None)
            res = nz.normalize_stp(raw, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, now=run.now(),
                                   history=getattr(ctx, "history", None), vlans=getattr(ctx, "vlans", ()))
        elif spec.parser_id == "mac.table":
            res = nz.normalize_mac_table(raw, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, now=run.now(),
                                         history=getattr(getattr(self, "l2_context", None), "history", None))
        elif spec.parser_id == "acl.rules":
            res = nz.normalize_acl_rules(raw, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, now=run.now(),
                                         history=getattr(getattr(self, "acl_context", None), "history", None))
        elif spec.parser_id == "acl.attachment":
            res = nz.normalize_acl_attachment(raw, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, now=run.now())
        elif spec.parser_id == "l2.port":
            res = nz.normalize_l2_ports(raw, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, now=run.now())
        elif spec.parser_id in ("route.table", "neighbor.table"):
            fn = nz.normalize_routes if spec.parser_id == "route.table" else nz.normalize_neighbor_table
            res = fn(raw, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, now=run.now(),
                     family="ipv6" if spec.key in FORWARDING_V6_KEYS else ("ipv4" if spec.key in FORWARDING_V4_KEYS else None))
        else:
            res = nz.normalize_neighbors(raw, parser_id=spec.parser_id, platform=target.platform, os_version=target.os_version, device=target.device,
                                         evidence=evidence, now=run.now())
        run.observations.extend(res["observations"])
        run.missing.extend(res["missing"])
        if res.get("parser"):
            evidence["parser"] = res["parser"]


# --------------------------------------------------------------------------------------------------------------------
# DNS (typed, bounded, read-only; the query itself is performed by an injected authorized runner -- this module never opens a socket)
# --------------------------------------------------------------------------------------------------------------------
DNS_MAX_RESPONSE_BYTES = 65_536
_DNS_NEEDS = {"resolver_config": (), "time_sync": (), "transport": ("server",), "query": ("name", "qtype", "server", "role"), "soa": ("zone", "server", "role"),
              "zone_status": ("zone", "server"), "delegation": ("zone",), "records": ("name",), "dnssec": ("zone", "server")}


@dataclass(frozen=True)
class DnsRequest:
    """One typed DNS diagnostic.  ``role`` (``recursive`` | ``authoritative``) states what the server is EXPECTED to be: the answer is judged as such, never guessed."""

    op: str
    server: str = ""
    name: str = ""
    zone: str = ""
    qtype: str = ""
    role: str = ""
    transport: str = "udp"
    aaaa_expected: bool | None = None

    def validate(self, allowed_servers: Iterable[str] | None = None) -> tuple["DnsRequest | None", list[str]]:
        """(normalised request, errors).  A request with errors is never handed to the runner."""
        errors: list[str] = []
        if self.op not in nz.DNS_OPS:
            return None, [f"operation {self.op!r} is not a permitted DNS diagnostic ({', '.join(nz.DNS_OPS)})"]
        fields = {"server": self.server, "name": self.name, "zone": self.zone, "qtype": str(self.qtype).upper(), "role": self.role, "transport": str(self.transport).lower()}
        for need in _DNS_NEEDS[self.op]:
            if not fields[need]:
                errors.append(f"{self.op} requires {need}")
        if fields["qtype"]:
            if fields["qtype"] in nz.DNS_REFUSED_QTYPES:
                errors.append(f"query type {fields['qtype']} is not permitted (zone transfers, ANY and unvalidated types are refused)")
            elif fields["qtype"] not in nz.DNS_QTYPES:
                errors.append(f"query type {fields['qtype'][:12]} unsupported")
        if self.op == "soa":
            fields["qtype"] = "SOA"
        if fields["transport"] not in ("udp", "tcp"):
            errors.append("transport must be udp or tcp")
        if fields["role"] and fields["role"] not in ("recursive", "authoritative"):
            errors.append("role must be recursive or authoritative")
        for f in ("name", "zone"):
            if fields[f]:
                fields[f], err = nz.validate_dns_name(fields[f], what=f)
                if err:
                    errors.append(err)
        if fields["server"]:
            fields["server"], err = nz.validate_dns_server(fields["server"])
            if err:
                errors.append(err)
            elif allowed_servers is not None and fields["server"] not in {nz.validate_dns_server(a)[0] for a in allowed_servers}:
                errors.append(f"server {fields['server']} is not an authorized DNS target for this case")
        if not errors and len(DnsRequest(self.op, fields["server"] or "", fields["name"] or "", fields["zone"] or "").engine_key()) > 120:
            errors.append("name/zone/server too long for a 128-character evidence key")
        if errors:
            return None, errors
        return DnsRequest(self.op, fields["server"] or "", fields["name"] or "", fields["zone"] or "", fields["qtype"], fields["role"], fields["transport"], self.aaaa_expected), []

    def as_dict(self) -> dict:
        return {"op": self.op, "server": self.server, "name": self.name, "zone": self.zone, "qtype": self.qtype, "role": self.role, "transport": self.transport,
                "aaaa_expected": self.aaaa_expected}

    def command(self) -> str:
        parts = [f"dns:{self.op}"] + [f"{k}={v}" for k, v in (("name", self.name), ("zone", self.zone), ("type", self.qtype), ("server", self.server), ("proto", self.transport)) if v]
        return " ".join(parts)

    def engine_key(self) -> str:
        key, subject = nz.dns_engine_key(self.as_dict())
        return f"{key}@{subject}" if subject else key


def _dns_probe(base: CapabilityProbe | None) -> CapabilityProbe:
    """DNS capability is carried by the injected runner itself; every other source keeps the caller's probe (fail closed)."""
    def probe(platform: str, source_type: str) -> dict:
        if source_type == SourceType.DNS_QUERY:
            return {"status": "SUPPORTED", "evidence": "injected authorized read-only DNS runner", "transport": "dns-runner"}
        return (base(platform, source_type) if base else {"status": "UNKNOWN"}) or {}
    return probe


class DnsCollector(_BaseCollector):
    """Typed DNS diagnostics through ``runner.execute(request_dict) -> JSON text`` (optional ``provenance()``).  The runner is the ONLY thing that touches a network;
    when it is absent the caller records an unavailable run (see ``runtime``).  Requests are validated before the runner is called; only ``READ_OPERATIONS`` exist."""

    source_type = SourceType.DNS_QUERY
    name = "dns"
    READ_OPERATIONS = frozenset(nz.DNS_OPS)

    def __init__(self, **kw):
        super().__init__(**kw)
        self.capability_probe = _dns_probe(self.capability_probe)

    def _dns_fail(self, run: _Run, req: DnsRequest | None, reason: str, detail: str, command: str, key: str = "") -> None:
        run.missing.append(missing_record(reason, source_type=run.source_type, device=run.target.device, detail=detail, command=command, observed_at=run.now(),
                                          extra={"engine_key": key} if key else None))

    def collect(self, target: Target, requests: Iterable[DnsRequest], runner, *, allowed_servers: Iterable[str] | None = None, transport_name: str = "dns-runner") -> dict:
        requests = list(requests)
        run, admission = self._run(target, transport_name)
        run.requested = len(requests)
        if not admission.ok:
            run.commands = [r.command() for r in requests]
            return _refuse(run, admission, ",".join(run.commands))
        allowed = list(allowed_servers) if allowed_servers is not None else None
        exhausted: str | None = None
        for raw_req in requests:
            req, errors = raw_req.validate(allowed)
            shown = (req or raw_req).command()
            key = (req or raw_req).engine_key()
            if req is None:
                self._dns_fail(run, None, Missing.COMMAND_NOT_ALLOWED, "; ".join(errors)[:240], shown, key)
                continue
            if exhausted:
                self._dns_fail(run, req, Missing.BUDGET_EXCEEDED, f"budget exhausted ({exhausted}) before {shown}", shown, key)
                continue
            exhausted = self._one(run, runner, req, shown, key, fallback=True)
        return run.bundle()

    def _one(self, run: _Run, runner, req: DnsRequest, shown: str, key: str, *, fallback: bool) -> str | None:
        run.commands.append(shown)
        try:
            raw, started, finished = self._execute(run, runner, req)
        except BudgetExceeded as exc:
            self._dns_fail(run, req, Missing.BUDGET_EXCEEDED, f"{exc.which} budget exhausted before/while running {shown}", shown, key)
            return exc.which
        except PermissionDenied:
            self._dns_fail(run, req, Missing.PERMISSION_DENIED, "runner reported permission denied", shown, key)
            return None
        except TimeoutError:
            self._dns_fail(run, req, Missing.TIMEOUT, f"runner timeout after {self.budget.max_retries + 1} attempt(s)", shown, key)
            return None
        except TransportError as exc:
            self._dns_fail(run, req, Missing.TRANSPORT_ERROR, exc.code, shown, key)
            return None
        if len(raw.encode("utf-8", "replace")) > min(self.budget.max_bytes, DNS_MAX_RESPONSE_BYTES):
            self._dns_fail(run, req, Missing.OUTPUT_TOO_LARGE, f"response exceeds {min(self.budget.max_bytes, DNS_MAX_RESPONSE_BYTES)} bytes; discarded", shown, key)
            return None
        status, detail = classify_output(raw)
        gw = getattr(runner, "provenance", None)
        gw = gw() if callable(gw) else None
        if gw:
            run.gateway = gw
        evidence = build_evidence(seq=run.next_seq(), source_type=SourceType.DNS_QUERY, transport=run.transport, adapter=self.adapter, device=run.target.device,
                                  platform=run.target.platform, os_version=run.target.os_version, command_or_api=shown, raw=raw, started_at=started, finished_at=finished,
                                  status=status, status_detail=detail, store=self.raw_store, gateway=gw)
        run.evidence.append(evidence)
        if status == "PERMISSION_DENIED":
            self._dns_fail(run, req, Missing.PERMISSION_DENIED, detail, shown, key)
            return None
        try:
            run.tracker.add_records(1)
        except BudgetExceeded as exc:
            self._dns_fail(run, req, Missing.BUDGET_EXCEEDED, f"{exc.which} budget exhausted", shown, key)
            return exc.which
        res = nz.normalize_dns(raw, request=req.as_dict(), device=run.target.device, evidence=evidence, now=run.now())
        evidence["parser"] = res.get("parser")
        truncated = any("DNS_TRUNCATED" in o.get("flags", []) for o in res["observations"])
        if truncated and fallback and req.transport == "udp":
            # the UDP answer was truncated: its raw evidence is kept, but no observation is emitted from it; ask again over TCP once (counted against the budget)
            run.flags.append(f"DNS_UDP_TRUNCATED_TCP_RETRY:{key}")
            tcp = DnsRequest(req.op, req.server, req.name, req.zone, req.qtype, req.role, "tcp", req.aaaa_expected)
            return self._one(run, runner, tcp, tcp.command(), key, fallback=False)
        run.observations.extend(res["observations"])
        run.missing.extend(res["missing"])
        return None

    def _execute(self, run: _Run, runner, req: DnsRequest):
        attempts = 0
        wire = {**req.as_dict(), "schema": "nmas.dns.request/1", "timeout_s": self.budget.per_command_timeout_s, "read_only": True}
        while True:
            run.tracker.before_request()
            attempts += 1
            started = run.now()
            try:
                raw = runner.execute(dict(wire))
                if not isinstance(raw, (str, bytes)):
                    raw = json.dumps(raw, sort_keys=True, default=str)
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", "replace")
                run.tracker.add_bytes(len(raw.encode("utf-8", "replace")))
                return raw, started, run.now()
            except (TimeoutError, TransportError) as exc:
                transient = isinstance(exc, TimeoutError) or exc.transient
                if not transient or attempts > self.budget.max_retries:
                    raise
                run.tracker.retries += 1
                self._sleep(self.budget.backoff_s * attempts)


# --------------------------------------------------------------------------------------------------------------------
# Active probes: bounded TCP connect + path trace through an injected runner (adapters/probes.py owns contracts and parsing)
# --------------------------------------------------------------------------------------------------------------------
PROBE_MAX_RESPONSE_BYTES = 65_536
PROBE_OPS = ("tcp_connect", "path_trace", "pmtu_probe")


@dataclass(frozen=True)
class ProbePolicy:
    """Authorization + scope of ONE case's active probes.  ``deny_reason`` non-empty => nothing is sent."""

    authorization_id: str = ""
    expires_at: datetime | None = None
    deny_reason: str = ""
    admitted_sources: tuple = ()
    destinations: tuple = ()
    ports: tuple = ()
    flow: dict = field(default_factory=dict)
    max_count: int = 5
    max_probes: int = 10
    max_hops: int = 30
    methods: tuple = ("tcp", "udp", "icmp")
    pmtu_authorized: bool = False
    pmtu_protocols: tuple = ()
    pmtu_families: tuple = ()
    pmtu_max_per_size: int = 3
    pmtu_max_sizes: int = 8
    pmtu_max_payload: int = 9000
    pmtu_max_packet_bytes: int = 40_000
    pmtu_max_pps: int = 5
    pmtu_max_seconds: float = 30.0


@dataclass(frozen=True)
class ProbeRequest:
    op: str
    src: str = ""
    src_address: str = ""
    dst: str = ""
    dst_address: str = ""
    protocol: str = ""
    port: int = 0
    count: int = 0
    method: str = ""
    max_hops: int = 0
    sizes: tuple = ()               # pmtu_probe: requested L4 payload sizes (bytes); ``count`` = trials per size
    family: str = ""
    df: bool = True
    required_payload: int = 0
    rate_pps: int = 0
    max_seconds: float = 0.0

    def packets(self) -> int:
        return len(self.sizes) * self.count if self.op == "pmtu_probe" and isinstance(self.count, int) else 0

    def max_packet_bytes(self) -> int:
        hdr = (40 if self.family == "ipv6" else 20) + 8
        return sum(s + hdr for s in self.sizes) * self.count

    def command(self) -> str:
        if self.op == "pmtu_probe":
            return (f"probe:pmtu_probe src={self.src} dst={self.dst}({self.dst_address}) proto={self.protocol} df={self.df} sizes={','.join(map(str, self.sizes))} "
                    f"per_size={self.count} rate_pps={self.rate_pps}")
        return self._command()

    def _command(self) -> str:
        if self.op == "tcp_connect":
            return f"probe:tcp_connect src={self.src} dst={self.dst}({self.dst_address}) port={self.port} count={self.count}"
        return f"probe:path_trace src={self.src} dst={self.dst}({self.dst_address}) method={self.method} max_hops={self.max_hops}"

    def engine_key(self) -> str:
        return "service.probe@tcp" if self.op == "tcp_connect" else f"path.pmtu@{self.dst}" if self.op == "pmtu_probe" else f"path.trace@{self.dst}"

    def cost(self) -> int:
        return self.count if self.op == "tcp_connect" else self.packets() if self.op == "pmtu_probe" else self.max_hops

    def validate(self, policy: ProbePolicy, now: datetime, target_device: str) -> list[str]:
        """Scope errors (empty => allowed).  Authorization problems are checked separately (they map to PERMISSION_DENIED)."""
        e: list[str] = []
        flow = policy.flow or {}
        if self.op not in PROBE_OPS:
            return [f"operation {self.op!r} is not a permitted probe ({', '.join(PROBE_OPS)})"]
        if not (self.src and self.src == target_device and self.src in policy.admitted_sources):
            e.append("source is not the collecting device or not an admitted probe source")
        if not (flow.get("src") == self.src and flow.get("dst") == self.dst):
            e.append("source/destination differ from the case flow tuple")
        if self.dst not in policy.destinations and self.dst_address not in policy.destinations:
            e.append("destination is not an authorized probe destination")
        try:
            ip = ipaddress.ip_address(self.dst_address)
            if ip.is_multicast or ip.is_unspecified or (ip.version == 4 and int(ip) == 0xFFFFFFFF):
                e.append("destination address is multicast/unspecified/broadcast")
        except ValueError:
            e.append("destination has no resolvable IP address (address book entry missing)")
        if self.op == "tcp_connect":
            if flow.get("protocol") != "tcp" or self.protocol != "tcp":
                e.append("only TCP is probed and the case flow must be TCP")
            if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535 or self.port != flow.get("port"):
                e.append("port is not the case flow port")
            elif self.port not in policy.ports:
                e.append("port is not an authorized probe port")
            if isinstance(self.count, bool) or not isinstance(self.count, int) or not 1 <= self.count <= policy.max_count:
                e.append(f"count must be 1..{policy.max_count}")
        elif self.op == "pmtu_probe":
            e += self._validate_pmtu(policy, flow)
        else:
            if self.method not in policy.methods:
                e.append("trace method not permitted")
            if self.method == "tcp" and (self.port not in policy.ports or self.port != flow.get("port")):
                e.append("tcp trace port is not the authorized case flow port")
            if isinstance(self.max_hops, bool) or not isinstance(self.max_hops, int) or not 1 <= self.max_hops <= policy.max_hops:
                e.append(f"max_hops must be 1..{policy.max_hops}")
        return e

    def _validate_pmtu(self, policy: ProbePolicy, flow: dict) -> list[str]:
        e: list[str] = []
        try:
            fam = "ipv6" if ipaddress.ip_address(self.dst_address).version == 6 else "ipv4"
        except ValueError:
            fam = ""
        if not fam or self.family != fam or fam not in policy.pmtu_families:
            e.append("address family is not the destination's or is not authorized for size probes")
        if self.protocol not in policy.pmtu_protocols or self.protocol not in ("icmp", "udp"):
            e.append("size-probe protocol is not authorized (only ICMP/UDP; TCP production behaviour is never probed with sizes)")
        if self.protocol == "udp" and (isinstance(self.port, bool) or not isinstance(self.port, int) or self.port not in policy.ports):
            e.append("udp size-probe port is not an authorized probe port")
        if self.df is not True:
            e.append("size probes must set DF")
        sizes_ok = (isinstance(self.sizes, tuple) and self.sizes and all(isinstance(s, int) and not isinstance(s, bool) and 1 <= s <= policy.pmtu_max_payload for s in self.sizes)
                    and len(set(self.sizes)) == len(self.sizes))
        if not sizes_ok or len(self.sizes) > policy.pmtu_max_sizes:
            e.append(f"sizes must be 1..{policy.pmtu_max_sizes} distinct payloads of 1..{policy.pmtu_max_payload} bytes")
        if isinstance(self.count, bool) or not isinstance(self.count, int) or not 1 <= self.count <= policy.pmtu_max_per_size:
            e.append(f"trials per size must be 1..{policy.pmtu_max_per_size}")
        if isinstance(self.rate_pps, bool) or not isinstance(self.rate_pps, int) or not 1 <= self.rate_pps <= policy.pmtu_max_pps:
            e.append(f"rate must be 1..{policy.pmtu_max_pps} pps")
        if not isinstance(self.max_seconds, (int, float)) or isinstance(self.max_seconds, bool) or not 0 < self.max_seconds <= policy.pmtu_max_seconds:
            e.append(f"time budget must be 0..{policy.pmtu_max_seconds} s")
        elif sizes_ok and isinstance(self.count, int) and isinstance(self.rate_pps, int) and self.rate_pps > 0 and self.packets() / self.rate_pps > self.max_seconds:
            e.append("packets at the stated rate do not fit the time budget")
        if sizes_ok and isinstance(self.count, int) and self.max_packet_bytes() > policy.pmtu_max_packet_bytes:
            e.append(f"wire bytes {self.max_packet_bytes()} exceed the {policy.pmtu_max_packet_bytes}-byte budget")
        return e

    def wire(self, policy: ProbePolicy, timeout_s: float) -> dict:
        w = {"schema": "nmas.probe.request/1", "op": self.op, "source": {"device": self.src, "address": self.src_address or None},
             "destination": {"name": self.dst, "address": self.dst_address}, "timeout_s": timeout_s, "active_probe": True, "mutating": False,
             "authorization_id": policy.authorization_id, "flow": {k: policy.flow.get(k) for k in ("src", "dst", "protocol", "port")}}
        if self.op == "tcp_connect":
            w.update(protocol="tcp", port=self.port, count=self.count)
        elif self.op == "pmtu_probe":
            w.update(protocol=self.protocol, family=self.family, port=self.port or None, df=True, payload_sizes=list(self.sizes), per_size=self.count, rate_pps=self.rate_pps,
                     max_seconds=self.max_seconds, max_packets=self.packets(), max_packet_bytes=self.max_packet_bytes(), observe_ptb=True)
        else:
            w.update(method=self.method, max_hops=self.max_hops, port=self.port if self.method == "tcp" else None)
        return w


def _probe_cap(base: CapabilityProbe | None) -> CapabilityProbe:
    """Probe capability is carried by the injected runner (``capabilities()``); every other source keeps the caller's probe (fail closed)."""
    def probe(platform: str, source_type: str) -> dict:
        if source_type == SourceType.ACTIVE_PROBE:
            return {"status": "SUPPORTED", "evidence": "injected runner; per-op capability checked via runner.capabilities()", "transport": "probe-runner"}
        return (base(platform, source_type) if base else {"status": "UNKNOWN"}) or {}
    return probe


class ProbeCollector(_BaseCollector):
    """``service.probe`` / ``path.trace`` through ``runner.execute(request_dict) -> JSON text``.  The runner is the ONLY thing that touches a network; there is no
    default.  Gates, in order: admission -> authorization (case-bound, unexpired) -> runner capability -> scope -> total attempt budget -> runner -> parse."""

    source_type = SourceType.ACTIVE_PROBE
    name = "probe"
    READ_OPERATIONS = frozenset(PROBE_OPS)

    def __init__(self, **kw):
        super().__init__(**kw)
        self.capability_probe = _probe_cap(self.capability_probe)
        self.context = None      # adapters.probes.ProbeContext (hop-owner address book) -- set by the runtime

    def _pfail(self, run: _Run, reason: str, detail: str, command: str, key: str) -> None:
        run.missing.append(missing_record(reason, source_type=run.source_type, device=run.target.device, detail=detail[:240], command=command, observed_at=run.now(),
                                          extra={"engine_key": key}))

    def collect(self, target: Target, requests: Iterable[ProbeRequest], runner, policy: ProbePolicy | None, *, transport_name: str = "probe-runner") -> dict:
        from .adapters import probes as pr
        requests = list(requests)
        run, admission = self._run(target, transport_name)
        run.requested = len(requests)
        if not admission.ok:
            run.commands = [r.command() for r in requests]
            return _refuse(run, admission, ",".join(run.commands))
        caps_fn = getattr(runner, "capabilities", None)
        try:
            caps = set(caps_fn()) if callable(caps_fn) else set()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            caps = set()
        spent = spent_bytes = 0
        exhausted: str | None = None
        for req in requests:
            shown, key = req.command(), req.engine_key()
            if policy is None:
                self._pfail(run, Missing.NOT_CONFIGURED, "no probe policy/context is configured; active probes are not sent", shown, key)
                continue
            if policy.deny_reason or policy.expires_at is None or run.now() >= policy.expires_at:
                why = policy.deny_reason or "active-probe authorization has expired"
                self._pfail(run, Missing.PERMISSION_DENIED, why, shown, key)
                continue
            if req.op == "pmtu_probe" and not policy.pmtu_authorized:
                self._pfail(run, Missing.PERMISSION_DENIED, "the case authorization does not cover size-dependent (pmtu_probe) probes", shown, key)
                continue
            if req.op not in caps:
                self._pfail(run, Missing.UNSUPPORTED_OPERATION, f"runner does not declare capability {req.op}", shown, key)
                continue
            errors = req.validate(policy, run.now(), target.device)
            if errors:
                self._pfail(run, Missing.COMMAND_NOT_ALLOWED, "; ".join(errors), shown, key)
                continue
            if req.op == "pmtu_probe" and spent_bytes + req.max_packet_bytes() > policy.pmtu_max_packet_bytes:
                self._pfail(run, Missing.BUDGET_EXCEEDED, f"probe byte budget exhausted before {shown}", shown, key)
                continue
            if exhausted or (req.op in ("tcp_connect", "pmtu_probe") and spent + req.cost() > policy.max_probes):
                self._pfail(run, Missing.BUDGET_EXCEEDED, f"probe budget exhausted ({exhausted or 'ATTEMPTS'}) before {shown}", shown, key)
                continue
            if req.op in ("tcp_connect", "pmtu_probe"):
                spent += req.cost()
            if req.op == "pmtu_probe":
                spent_bytes += req.max_packet_bytes()
            exhausted = self._one(run, runner, req, policy, shown, key, pr)
        return run.bundle()

    def _one(self, run: _Run, runner, req: ProbeRequest, policy: ProbePolicy, shown: str, key: str, pr) -> str | None:
        run.commands.append(shown)
        timeout = self.budget.per_command_timeout_s
        try:
            run.tracker.before_request()
        except BudgetExceeded as exc:
            self._pfail(run, Missing.BUDGET_EXCEEDED, f"{exc.which} budget exhausted before {shown}", shown, key)
            return exc.which
        started = run.now()
        try:
            raw = runner.execute(req.wire(policy, timeout))      # exactly one attempt: a retry would be extra traffic on a possibly impaired path
            if not isinstance(raw, (str, bytes)):
                raw = json.dumps(raw, sort_keys=True, default=str)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
        except PermissionDenied:
            self._pfail(run, Missing.PERMISSION_DENIED, "runner reported permission denied", shown, key)
            return None
        except TimeoutError:
            self._pfail(run, Missing.TIMEOUT, "runner timeout (no retry for active probes)", shown, key)
            return None
        except TransportError as exc:
            self._pfail(run, Missing.TRANSPORT_ERROR, exc.code, shown, key)
            return None
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            self._pfail(run, Missing.TRANSPORT_ERROR, f"runner_error:{type(exc).__name__}", shown, key)
            return None
        finished = run.now()
        size = len(raw.encode("utf-8", "replace"))
        if size > min(self.budget.max_bytes, PROBE_MAX_RESPONSE_BYTES):
            self._pfail(run, Missing.OUTPUT_TOO_LARGE, f"response exceeds {min(self.budget.max_bytes, PROBE_MAX_RESPONSE_BYTES)} bytes; discarded", shown, key)
            return None
        try:
            run.tracker.add_bytes(size)
        except BudgetExceeded as exc:
            self._pfail(run, Missing.BUDGET_EXCEEDED, f"{exc.which} budget exhausted", shown, key)
            return exc.which
        gw = getattr(runner, "provenance", None)
        gw = gw() if callable(gw) else None
        if gw:
            run.gateway = gw
        status, detail = classify_output(raw)
        meta = dict(pr.PARSERS[req.op])
        evidence = build_evidence(seq=run.next_seq(), source_type=SourceType.ACTIVE_PROBE, transport=run.transport, adapter=self.adapter, device=run.target.device,
                                  platform=run.target.platform, os_version=run.target.os_version, command_or_api=shown, raw=raw, started_at=started, finished_at=finished,
                                  status=status, status_detail=detail, store=self.raw_store, gateway=gw, parser=meta)
        run.evidence.append(evidence)
        if status == "PERMISSION_DENIED":
            self._pfail(run, Missing.PERMISSION_DENIED, detail, shown, key)
            return None
        try:
            parsed = pr.parse_response(raw, req, timeout_s=timeout, ctx=self.context)
        except pr.ProbeBad as exc:
            self._pfail(run, Missing.PARSE_FAILED, str(exc), shown, key)
            return None
        run.observations.append(make_observation(parsed["key"], parsed["value"], device=run.target.device, evidence=evidence, observed_at=parsed["observed_at"],
                                                 target={"probe": parsed["subject"]}, quality=parsed["quality"], parser=meta, now=run.now(), flags=parsed["flags"]))
        return None


# --------------------------------------------------------------------------------------------------------------------
# gNMI / OpenConfig
# --------------------------------------------------------------------------------------------------------------------
GNMI_ALLOWED_PREFIXES = ("/interfaces/interface", "/system/state", "/system/cpus", "/system/memory", "/components/component", "/lldp",
                         "/network-instances/network-instance", "/openconfig-interfaces:interfaces")
MIN_SAMPLE_INTERVAL_NS = 5_000_000_000


class GnmiCollector(_BaseCollector):
    """gNMI Capabilities / Get / Subscribe(STREAM|POLL|ONCE).  Set is refused.  ``source`` (stream) is an iterable/callable of
    notifications ``{"timestamp": ns, "prefix":..., "update":[...], "_arrival": iso?}`` supplied by an adapter."""

    source_type = SourceType.GNMI_STREAM
    name = "gnmi"
    READ_OPERATIONS = frozenset({"capabilities", "get", "subscribe"})

    @staticmethod
    def validate_paths(paths: Iterable[str], allowed: Iterable[str] = GNMI_ALLOWED_PREFIXES) -> list[str]:
        bad = [p for p in paths if not any(str(p).startswith(a) for a in allowed)]
        return bad

    def subscribe(self, target: Target, paths: list[str], source, *, sample_interval_ns: int = 20_000_000_000, stream_mode: str = "SAMPLE",
                  mode: str = "STREAM", allowed_prefixes: Iterable[str] = GNMI_ALLOWED_PREFIXES, clock_model: dict | None = None,
                  max_notifications: int | None = None, transport_name: str = "gnmi") -> dict:
        run, admission = self._run(target, transport_name)
        run.requested = len(paths)
        api = f"gNMI Subscribe {mode}/{stream_mode} {','.join(paths)} @{sample_interval_ns}ns"
        run.commands.append(api)
        if not admission.ok:
            return _refuse(run, admission, api)
        if mode not in ("STREAM", "POLL", "ONCE") or stream_mode not in ("SAMPLE", "ON_CHANGE", "TARGET_DEFINED"):
            return _refuse(run, Admission(False, Missing.UNSUPPORTED_OPERATION, f"invalid subscription mode {mode}/{stream_mode}"), api)
        bad = self.validate_paths(paths, allowed_prefixes)
        if bad or not paths:
            return _refuse(run, Admission(False, Missing.COMMAND_NOT_ALLOWED, f"paths outside the OpenConfig read allowlist: {bad or 'none given'}"), api)
        if stream_mode == "SAMPLE" and sample_interval_ns < MIN_SAMPLE_INTERVAL_NS:
            return _refuse(run, Admission(False, Missing.BUDGET_EXCEEDED, f"sample interval {sample_interval_ns}ns below the {MIN_SAMPLE_INTERVAL_NS}ns rate bound"), api)
        limit = min(max_notifications or self.budget.max_records, self.budget.max_records)
        buffer = BoundedBuffer(limit)
        started = run.now()
        try:
            iterator = source() if callable(source) else iter(source)
            run.tracker.before_request()
            for notification in iterator:
                if run.tracker.elapsed() >= self.budget.max_seconds:
                    raise BudgetExceeded("TIME")
                buffer.offer(notification)
        except BudgetExceeded as exc:
            self._fail(run, Missing.BUDGET_EXCEEDED, f"{exc.which} budget exhausted; stream cut after {len(buffer.items)} notification(s)", api)
        except PermissionDenied:
            self._fail(run, Missing.PERMISSION_DENIED, "gNMI server denied the subscription", api)
            return run.bundle()
        except (TimeoutError, TransportError) as exc:
            self._fail(run, Missing.TIMEOUT if isinstance(exc, TimeoutError) else Missing.TRANSPORT_ERROR, "stream interrupted", api)
        finished = run.now()
        raw = json.dumps(buffer.items, sort_keys=True, default=str)
        if buffer.dropped:
            run.flags.append("DATA_LOSS")
            self._fail(run, Missing.BUDGET_EXCEEDED, f"backpressure: {buffer.dropped} notification(s) rejected (buffer {limit})", api)
        if not buffer.items:
            if not run.missing:
                self._fail(run, Missing.EMPTY, "no notifications received", api)
            return run.bundle(extra={"stream": {"received": 0, "dropped_count": buffer.dropped}})
        evidence = build_evidence(seq=run.next_seq(), source_type=SourceType.GNMI_STREAM if mode == "STREAM" else SourceType.GNMI_GET, transport=transport_name,
                                  adapter=self.adapter, device=target.device, platform=target.platform, os_version=target.os_version, command_or_api=api,
                                  raw=raw, started_at=started, finished_at=finished, status="OK" if not buffer.dropped else "PARTIAL", store=self.raw_store,
                                  coverage={"notifications": len(buffer.items), "dropped": buffer.dropped, "sample_interval_ns": sample_interval_ns, "stream_mode": stream_mode},
                                  freshness_max_age_s=max(SOURCE_PROFILES[SourceType.GNMI_STREAM]["freshness_max_age_s"], 3 * sample_interval_ns / 1e9))
        run.evidence.append(evidence)
        unmapped: list[str] = []
        for notification in buffer.items:
            arrival = to_utc(notification["_arrival"]) if notification.get("_arrival") else finished
            res = nz.normalize_gnmi_notification(notification, device=target.device, platform=target.platform, evidence=evidence, arrival=arrival, now=run.now(),
                                                 clock=clock_model)
            run.observations.extend(res["observations"])
            unmapped.extend(res["unmapped_paths"])
        return run.bundle(extra={"stream": {"received": len(buffer.items), "dropped_count": buffer.dropped, "unmapped_paths": sorted(set(unmapped)), "mode": mode}})

    def get(self, target: Target, paths: list[str], getter, *, clock_model: dict | None = None) -> dict:
        """Poll mode: ``getter(paths) -> list of notifications`` (a single Get)."""
        return self.subscribe(target, paths, lambda: getter(paths), mode="ONCE", stream_mode="TARGET_DEFINED", clock_model=clock_model, transport_name="gnmi-get")

    def set(self, target: Target, *a, **k) -> dict:
        return self.refuse_operation(target, "gNMI Set")


# --------------------------------------------------------------------------------------------------------------------
# SNMP
# --------------------------------------------------------------------------------------------------------------------
SNMP_ALLOWED_PREFIXES = ("1.3.6.1.2.1.1.", "1.3.6.1.2.1.2.2.1.", "1.3.6.1.2.1.31.1.1.1.", "1.3.6.1.2.1.25.3.3.1.", "1.3.6.1.6.3.10.2.1.1")
IF_TABLE_COLUMNS = {
    "ifName": "1.3.6.1.2.1.31.1.1.1.1", "ifMtu": "1.3.6.1.2.1.2.2.1.4", "ifSpeed": "1.3.6.1.2.1.2.2.1.5", "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8", "ifInOctets": "1.3.6.1.2.1.2.2.1.10", "ifInDiscards": "1.3.6.1.2.1.2.2.1.13", "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16", "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19", "ifOutErrors": "1.3.6.1.2.1.2.2.1.20", "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6", "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
}
SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"


class SnmpCollector(_BaseCollector):
    """SNMP GET/GETNEXT/WALK only (SET refused).  ``session`` has ``walk(oid) -> {oid: value}`` and ``get(oid) -> value``; it holds the
    credentials (never serialized).  The tracker persists across polls so wraps/resets/gaps are detected between them."""

    source_type = SourceType.SNMP_POLL
    name = "snmp"
    READ_OPERATIONS = frozenset({"get", "getnext", "walk"})

    def __init__(self, *args, jitter_fraction: float = 0.1, rng: random.Random | None = None, poll_interval_s: float = 60.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.tracker = nz.CounterTracker(max_gap_s=3.0 * poll_interval_s)
        self.jitter_fraction, self.rng, self.poll_interval_s = jitter_fraction, rng or random.Random(), poll_interval_s

    def next_poll_delay(self) -> float:
        """Poll period with +/- jitter (avoids synchronized polling); never below the profile minimum."""
        base = max(self.poll_interval_s, SOURCE_PROFILES[SourceType.SNMP_POLL]["min_sampling_s"])
        return max(SOURCE_PROFILES[SourceType.SNMP_POLL]["min_sampling_s"], base * (1 + self.rng.uniform(-self.jitter_fraction, self.jitter_fraction)))

    def poll(self, target: Target, session, *, columns: Iterable[str] = tuple(IF_TABLE_COLUMNS), clock_model: dict | None = None, include_uptime: bool = True,
             transport_name: str = "snmp") -> dict:
        columns = [c for c in columns]
        run, admission = self._run(target, transport_name)
        run.requested = len(columns) + (1 if include_uptime else 0)
        if not admission.ok:
            return _refuse(run, admission, "snmp-walk")
        unknown = [c for c in columns if c not in IF_TABLE_COLUMNS]
        if unknown:
            return _refuse(run, Admission(False, Missing.COMMAND_NOT_ALLOWED, f"columns not in the IF-MIB allowlist: {unknown}"), "snmp-walk")
        started = run.now()
        oids: dict[str, Any] = {}
        uptime = None
        try:
            for column in columns:
                oid = IF_TABLE_COLUMNS[column]
                if not oid.startswith(SNMP_ALLOWED_PREFIXES):
                    raise CommandNotAllowed(oid)
                run.tracker.before_request()
                run.commands.append(f"snmpwalk {oid}")
                oids.update({k: v for k, v in session.walk(oid).items() if str(k).startswith(oid + ".")})
            if include_uptime:
                run.tracker.before_request()
                run.commands.append(f"snmpget {SYS_UPTIME_OID}")
                uptime = session.get(SYS_UPTIME_OID)
        except BudgetExceeded as exc:
            self._fail(run, Missing.BUDGET_EXCEEDED, f"{exc.which} budget exhausted mid-poll; partial table discarded (a half table would fake missing interfaces)", "snmp-walk")
            return run.bundle()
        except PermissionDenied:
            self._fail(run, Missing.PERMISSION_DENIED, "SNMP authentication/authorization failed", "snmp-walk")
            return run.bundle()
        except TimeoutError:
            self._fail(run, Missing.TIMEOUT, "SNMP request timed out", "snmp-walk")
            return run.bundle()
        except (TransportError, CommandNotAllowed) as exc:
            self._fail(run, Missing.TRANSPORT_ERROR, getattr(exc, "code", str(exc)), "snmp-walk")
            return run.bundle()
        finished = run.now()
        if not oids:
            self._fail(run, Missing.EMPTY, "walk returned no IF-MIB rows", "snmp-walk")
            return run.bundle()
        raw = json.dumps(oids, sort_keys=True, default=str)
        evidence = build_evidence(seq=run.next_seq(), source_type=SourceType.SNMP_POLL, transport=transport_name, adapter=self.adapter, device=target.device,
                                  platform=target.platform, os_version=target.os_version, command_or_api="snmpwalk IF-MIB", raw=raw, started_at=started,
                                  finished_at=finished, status="OK", store=self.raw_store, coverage={"columns": columns, "rows": len(oids)},
                                  freshness_max_age_s=3 * self.poll_interval_s)
        run.evidence.append(evidence)
        try:
            parsed = nz.parse_snmp_if_mib(oids)
        except ValueError as exc:
            self._fail(run, Missing.PARSE_FAILED, str(exc)[:200], "snmpwalk IF-MIB")
            return run.bundle()
        res = nz.normalize_snmp_poll(parsed.records, device=target.device, evidence=evidence, tracker=self.tracker, now=run.now(), platform=target.platform,
                                     sys_uptime_ticks=int(uptime) if isinstance(uptime, (int, float)) and not isinstance(uptime, bool) else None)
        run.observations.extend(res["observations"])
        evidence["parser"] = {"id": "interfaces.snmp", "version": "snmp-if-mib-1.0"}
        return run.bundle()

    def set(self, target: Target, *a, **k) -> dict:
        return self.refuse_operation(target, "SNMP SET")


# --------------------------------------------------------------------------------------------------------------------
# Syslog, NetFlow/IPFIX, capture metadata
# --------------------------------------------------------------------------------------------------------------------
class SyslogCollector(_BaseCollector):
    source_type = SourceType.SYSLOG
    name = "syslog"
    READ_OPERATIONS = frozenset({"read"})

    def collect(self, target: Target, lines: Iterable, *, clock_model: dict | None = None, tz=None, dedupe_window_s: float = 2.0,
                transport_name: str = "syslog-receiver") -> dict:
        """``lines``: iterable of ``(line, received_at)`` (received_at: datetime or ISO) from the existing receiver (adapter)."""
        run, admission = self._run(target, transport_name)
        run.commands.append("syslog read")
        if not admission.ok:
            return _refuse(run, admission, "syslog read")
        buffer = BoundedBuffer(self.budget.max_records)
        started = run.now()
        for item in lines:
            buffer.offer(item)
        run.requested = len(buffer.items) + buffer.dropped
        if buffer.dropped:
            run.flags.append("DATA_LOSS")
            self._fail(run, Missing.BUDGET_EXCEEDED, f"backpressure: {buffer.dropped} syslog line(s) beyond the {self.budget.max_records} record budget were not processed", "syslog read")
        if not buffer.items:
            self._fail(run, Missing.EMPTY, "no syslog lines in window", "syslog read")
            return run.bundle()
        raw = "\n".join(str(line) for line, _ in buffer.items)
        evidence = build_evidence(seq=run.next_seq(), source_type=SourceType.SYSLOG, transport=transport_name, adapter=self.adapter, device=target.device,
                                  platform=target.platform, os_version=target.os_version, command_or_api="syslog window", raw=raw, started_at=started,
                                  finished_at=run.now(), status="OK" if not buffer.dropped else "PARTIAL", store=self.raw_store,
                                  coverage={"lines": len(buffer.items), "dropped": buffer.dropped})
        run.evidence.append(evidence)
        events = []
        for index, (line, received) in enumerate(buffer.items):
            events.append(nz.parse_syslog_line(line, received_at=to_utc(received), tz=tz, device=target.device, evidence_ref=f"{evidence['evidence_id']}#L{index + 1}"))
        res = nz.normalize_syslog_events(events, evidence=evidence, device=target.device, clock=clock_model, dedupe_window_s=dedupe_window_s, now=run.now())
        run.observations.extend(res["observations"])
        return run.bundle(extra={"syslog": {"input_events": res["input_events"], "unique_events": res["unique_events"]}})


class FlowCollector(_BaseCollector):
    source_type = SourceType.NETFLOW
    name = "netflow"
    READ_OPERATIONS = frozenset({"read"})

    def collect(self, target: Target, records: Iterable[dict], selector: dict, *, expected_exporters: Iterable[str] = (), privacy: str = "prefix",
                transport_name: str = "ipfix-collector") -> dict:
        run, admission = self._run(target, transport_name)
        run.commands.append("flow query " + json.dumps(selector, sort_keys=True))
        if not admission.ok:
            return _refuse(run, admission, run.commands[-1])
        if not any(selector.get(k) for k in ("protocol", "dst_ports", "src_ports", "src_prefixes", "dst_prefixes")):
            return _refuse(run, Admission(False, Missing.COMMAND_NOT_ALLOWED, "UNSCOPED_FLOW_QUERY: a service selector is required (privacy/volume control)"), run.commands[-1])
        buffer = BoundedBuffer(self.budget.max_records)
        started = run.now()
        for rec in records:
            buffer.offer(rec)
        run.requested = len(buffer.items) + buffer.dropped
        if buffer.dropped:
            run.flags.append("DATA_LOSS")
            self._fail(run, Missing.BUDGET_EXCEEDED, f"backpressure: {buffer.dropped} flow record(s) not processed", run.commands[-1])
        raw = json.dumps(buffer.items, sort_keys=True, default=str)
        evidence = build_evidence(seq=run.next_seq(), source_type=SourceType.NETFLOW, transport=transport_name, adapter=self.adapter, device=target.device,
                                  platform=target.platform, os_version=target.os_version, command_or_api=run.commands[-1], raw=raw, started_at=started,
                                  finished_at=run.now(), status="OK" if not buffer.dropped else "PARTIAL", store=self.raw_store,
                                  coverage={"records": len(buffer.items), "dropped": buffer.dropped})
        run.evidence.append(evidence)
        res = nz.normalize_flow_records(buffer.items, selector, device=target.device, evidence=evidence, expected_exporters=expected_exporters, now=run.now(), privacy=privacy)
        run.observations.extend(res["observations"])
        evidence["coverage"].update(in_scope=res["in_scope"], out_of_scope=res["out_of_scope"], exporters=res["coverage"])
        if not res["in_scope"]:
            self._fail(run, Missing.EMPTY, "no flow record matched the service selector (absence of flows is NOT proof of no traffic: sampling/coverage apply)", run.commands[-1])
        return run.bundle()


class CaptureMetadataCollector(_BaseCollector):
    """Ingests metadata of an authorized, bounded capture performed by other tooling.  It never starts a capture and never forwards payload."""

    source_type = SourceType.PCAP_METADATA
    name = "pcap-metadata"
    READ_OPERATIONS = frozenset({"read"})

    @staticmethod
    def authorization_problem(auth: dict | None, meta: dict, device: str, now: datetime) -> str:
        if not auth:
            return "NO_AUTHORIZATION"
        for key in ("authorized_by", "ticket", "expires_at", "device", "interface"):
            if not auth.get(key):
                return f"AUTHORIZATION_MISSING_{key.upper()}"
        if to_utc(auth["expires_at"]) <= now:
            return "AUTHORIZATION_EXPIRED"
        if auth["device"] != device or canonical_interface(auth["interface"]) != canonical_interface(meta.get("interface", "")):
            return "AUTHORIZATION_SCOPE_MISMATCH"
        return ""

    def collect(self, target: Target, meta: dict, authorization: dict | None, *, bounds: dict | None = None, transport_name: str = "capture-runner") -> dict:
        run, admission = self._run(target, transport_name)
        run.commands.append(f"capture-metadata {meta.get('capture_id', '?')}")
        run.requested = 1
        if not admission.ok:
            return _refuse(run, admission, run.commands[-1])
        problem = self.authorization_problem(authorization, meta, target.device, run.now())
        if problem:
            run.refused = Admission(False, Missing.UNAUTHORIZED_CAPTURE, problem)
            self._fail(run, Missing.UNAUTHORIZED_CAPTURE, problem, run.commands[-1])
            return run.bundle()
        safe_meta = {k: v for k, v in meta.items() if k.lower() not in nz.PAYLOAD_KEYS}
        raw = json.dumps(safe_meta, sort_keys=True, default=str)   # payload never reaches evidence, even as a hash input
        evidence = build_evidence(seq=run.next_seq(), source_type=SourceType.PCAP_METADATA, transport=transport_name, adapter=self.adapter, device=target.device,
                                  platform=target.platform, os_version=target.os_version, command_or_api=run.commands[-1], raw=raw, started_at=run.now(),
                                  finished_at=run.now(), status="OK", store=self.raw_store,
                                  extra={"authorized_by": authorization["authorized_by"], "ticket": authorization["ticket"], "pcap_ref": meta.get("pcap_ref")})
        run.evidence.append(evidence)
        res = nz.normalize_capture_metadata(meta, device=target.device, evidence=evidence, bounds=bounds, now=run.now())
        run.observations.extend(res["observations"])
        run.missing.extend(res["missing"])
        if res["dropped_fields"]:
            run.flags.append("PAYLOAD_FIELDS_DROPPED:" + ",".join(res["dropped_fields"]))
        return run.bundle(extra={"capture": {"violations": res["violations"]}})


# --------------------------------------------------------------------------------------------------------------------
# NETCONF
# --------------------------------------------------------------------------------------------------------------------
NETCONF_FILTERS = {
    "interfaces": '<filter type="subtree"><interfaces xmlns="http://openconfig.net/yang/interfaces"><interface/></interfaces></filter>',
    "hostname": '<filter type="subtree"><system xmlns="http://openconfig.net/yang/system"><state><hostname/></state></system></filter>',
}
NETCONF_WRITE_RPCS = frozenset({"edit-config", "copy-config", "delete-config", "commit", "discard-changes", "lock", "unlock", "kill-session", "close-session",
                                "cancel-commit", "validate"})


def netconf_interfaces_xml_to_openconfig(xml_text: str) -> dict:
    """OpenConfig interfaces XML -> the JSON-IETF shape ``parse_openconfig_interfaces`` reads.  DTDs/entities are refused (XXE)."""
    if re.search(r"<!DOCTYPE|<!ENTITY", xml_text, re.I):
        raise ValueError("DTD/entity declarations are not accepted")
    root = ET.fromstring(xml_text)

    def local(tag):
        return tag.rsplit("}", 1)[-1]

    def children(node):
        return {local(c.tag): c for c in node}
    rows = []
    for iface in root.iter():
        if local(iface.tag) != "interface":
            continue
        kids = children(iface)
        state = children(kids["state"]) if "state" in kids else {}
        counters = children(state["counters"]) if "counters" in state else {}
        rows.append({"name": (kids["name"].text if "name" in kids else (state.get("name").text if state.get("name") is not None else "")),
                     "state": {**{k: v.text for k, v in state.items() if k != "counters"},
                               "counters": {k: int(v.text) for k, v in counters.items() if v.text and v.text.isdigit()}}})
    return {"openconfig-interfaces:interfaces": {"interface": rows}}


class NetconfCollector(_BaseCollector):
    source_type = SourceType.NETCONF
    name = "netconf"
    READ_OPERATIONS = frozenset({"get", "get-config"})

    def get(self, target: Target, rpc: str, filter_key: str, session, *, transport_name: str = "netconf") -> dict:
        """``session.execute(rpc, filter_xml) -> xml``.  Only ``get``/``get-config`` with a catalogued subtree filter."""
        if rpc in NETCONF_WRITE_RPCS or rpc not in self.READ_OPERATIONS:
            return self.refuse_operation(target, f"NETCONF {rpc}")
        run, admission = self._run(target, transport_name)
        api = f"NETCONF {rpc} filter={filter_key}"
        run.commands.append(api)
        run.requested = 1
        if not admission.ok:
            return _refuse(run, admission, api)
        if filter_key not in NETCONF_FILTERS:
            return _refuse(run, Admission(False, Missing.COMMAND_NOT_ALLOWED, f"filter {filter_key!r} is not catalogued"), api)
        started = run.now()
        try:
            run.tracker.before_request()
            raw = session.execute(rpc, NETCONF_FILTERS[filter_key])
            run.tracker.add_bytes(len(raw or ""))
        except BudgetExceeded as exc:
            self._fail(run, Missing.BUDGET_EXCEEDED, exc.which, api)
            return run.bundle()
        except PermissionDenied:
            self._fail(run, Missing.PERMISSION_DENIED, "NETCONF access-denied", api)
            return run.bundle()
        except TimeoutError:
            self._fail(run, Missing.TIMEOUT, "NETCONF timeout", api)
            return run.bundle()
        except TransportError as exc:
            self._fail(run, Missing.TRANSPORT_ERROR, exc.code, api)
            return run.bundle()
        evidence = build_evidence(seq=run.next_seq(), source_type=SourceType.NETCONF, transport=transport_name, adapter=self.adapter, device=target.device,
                                  platform=target.platform, os_version=target.os_version, command_or_api=api, raw=raw, started_at=started, finished_at=run.now(),
                                  status="OK", store=self.raw_store)
        run.evidence.append(evidence)
        if filter_key == "interfaces":
            try:
                converted = netconf_interfaces_xml_to_openconfig(raw)
            except (ET.ParseError, ValueError, KeyError) as exc:
                self._fail(run, Missing.PARSE_FAILED, str(exc)[:160], api)
                return run.bundle()
            res = nz.normalize_interfaces(converted, parser_id="interfaces.openconfig", platform=target.platform, os_version=target.os_version, device=target.device,
                                          evidence=evidence, now=run.now())
            run.observations.extend(res["observations"])
            run.missing.extend(res["missing"])
        return run.bundle()

    def edit_config(self, target: Target, *a, **k) -> dict:
        return self.refuse_operation(target, "NETCONF edit-config")


# --------------------------------------------------------------------------------------------------------------------
# Snapshots and intent inputs (config / state / NetBox / golden)
# --------------------------------------------------------------------------------------------------------------------
class ProviderCollector(_BaseCollector):
    """Collects from injected read-only providers: config/state snapshot readers, NetBox intent, golden-config lookups.  A provider that
    raises or returns nothing yields a missing record; a missing ``url`` is surfaced (``NO_OPERATOR_URL``), never invented."""

    name = "provider"

    def __init__(self, source_type: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if source_type not in (SourceType.CONFIG_SNAPSHOT, SourceType.STATE_SNAPSHOT, SourceType.NETBOX_INTENT, SourceType.GOLDEN_CONFIG):
            raise ValueError(f"not a provider source type: {source_type}")
        self.source_type = source_type

    def collect(self, target: Target, provider: Callable[[], dict], *, transport_name: str = "provider") -> dict:
        run, admission = self._run(target, transport_name)
        run.commands.append(f"{self.source_type.lower()} provider")
        run.requested = 1
        if not admission.ok:
            return _refuse(run, admission, run.commands[-1])
        started = run.now()
        try:
            run.tracker.before_request()
            payload = provider()
        except PermissionDenied:
            self._fail(run, Missing.PERMISSION_DENIED, "provider denied access", run.commands[-1])
            return run.bundle()
        except (TimeoutError, TransportError, OSError):
            self._fail(run, Missing.TRANSPORT_ERROR, "provider unavailable", run.commands[-1])
            return run.bundle()
        except BudgetExceeded as exc:
            self._fail(run, Missing.BUDGET_EXCEEDED, exc.which, run.commands[-1])
            return run.bundle()
        if not payload or payload.get("content") in (None, "", {}) and payload.get("intent") in (None, {}):
            self._fail(run, Missing.EMPTY, "provider returned no data", run.commands[-1])
            return run.bundle()
        is_intent = self.source_type in (SourceType.NETBOX_INTENT, SourceType.GOLDEN_CONFIG) and payload.get("intent") is not None
        raw = json.dumps(payload.get("intent"), sort_keys=True, default=str) if is_intent else (payload["content"] if isinstance(payload["content"], str) else json.dumps(payload["content"], sort_keys=True, default=str))
        evidence = build_evidence(seq=run.next_seq(), source_type=self.source_type, transport=transport_name, adapter=self.adapter, device=target.device,
                                  platform=target.platform, os_version=target.os_version, command_or_api=payload.get("api", run.commands[-1]), raw=raw,
                                  started_at=started, finished_at=run.now(), status="OK", store=self.raw_store,
                                  evidence_class=EvidenceClass.INTENT if is_intent else EvidenceClass.SNAPSHOT,
                                  extra={"revision": payload.get("revision"), "operator_url": payload.get("url"), "soak": payload.get("soak"),
                                         "approved_change_id": payload.get("approved_change_id")})
        run.evidence.append(evidence)
        if is_intent:
            res = nz.normalize_intent(target.device, payload["intent"], evidence=evidence, now=run.now(), source=payload.get("source", self.source_type.lower()),
                                      revision=payload.get("revision", ""), url=payload.get("url", ""))
        else:
            res = nz.normalize_snapshot(payload.get("kind", "config"), payload["content"], device=target.device, evidence=evidence, revision=payload.get("revision", ""),
                                        url=payload.get("url", ""), now=run.now())
        run.observations.extend(res["observations"])
        if not payload.get("url"):
            run.flags.append("NO_OPERATOR_URL")
        return run.bundle()


class FibCollector(_BaseCollector):
    """Bounded read-only collection from an injected independent forwarding-table source (HC16).

    ``reader`` is an object with ``read(request: dict) -> dict`` returning a ``nmas.troubleshooting.fib-source/1`` document (optionally ``.provenance()``).  The source
    type is STATE_SNAPSHOT (operational state); nothing here issues a device command, so the collector cannot mutate anything.  RIB / Linux ``ip route`` output is
    refused by normalization (``normalize_fib_state``); every refusal is a missing record bound to the asked ``route.fib@<prefix>`` keys."""

    name = "fib-source"
    source_type = SourceType.STATE_SNAPSHOT
    MAX_PREFIXES = 64

    def collect(self, target: Target, requests: Iterable[dict], reader, *, transport_name: str = "fib-source") -> dict:
        run, admission = self._run(target, transport_name)
        requests = list(requests)[:self.MAX_PREFIXES]
        run.requested = len(requests)
        run.commands.extend(f"fib-state read vrf={r.get('vrf')} family={r.get('family')}" for r in requests)
        if not admission.ok:
            return _refuse(run, admission, run.commands[0] if run.commands else "fib-state read")
        for req, shown in zip(requests, run.commands):
            request = {"vrf": str(req.get("vrf") or "default"), "family": req.get("family"), "prefixes": list(req.get("prefixes") or [])[:self.MAX_PREFIXES]}
            started = run.now()
            try:
                run.tracker.before_request()
                doc = reader.read(dict(request, device=target.device, platform=target.canonical_platform, os_version=target.os_version))
            except PermissionDenied:
                self._fail(run, Missing.PERMISSION_DENIED, "forwarding source denied access", shown)
                continue
            except (TimeoutError, TransportError, OSError):
                self._fail(run, Missing.TRANSPORT_ERROR, "forwarding source unavailable", shown)
                continue
            except BudgetExceeded as exc:
                self._fail(run, Missing.BUDGET_EXCEEDED, exc.which, shown)
                break
            raw = json.dumps(doc, sort_keys=True, default=str)
            prov = getattr(reader, "provenance", None)
            gw = prov() if callable(prov) else None
            if gw and run.gateway is None:
                run.gateway = gw
            try:
                run.tracker.add_bytes(len(raw.encode("utf-8", "replace")))
            except BudgetExceeded:
                self._fail(run, Missing.OUTPUT_TOO_LARGE, "forwarding document exceeds the byte budget", shown)
                continue
            evidence = build_evidence(seq=run.next_seq(), source_type=self.source_type, transport=transport_name, adapter=self.adapter, device=target.device,
                                      platform=target.platform, os_version=target.os_version, command_or_api=shown, raw=raw, started_at=started, finished_at=run.now(),
                                      status="OK", store=self.raw_store, evidence_class=EvidenceClass.OPERATIONAL, parser=dict(nz.FIB_PARSER), gateway=gw)
            run.evidence.append(evidence)
            res = nz.normalize_fib_state(doc, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, request=request, now=run.now())
            run.observations.extend(res["observations"])
            run.missing.extend(res["missing"])
        return run.bundle()


class QosCollector(_BaseCollector):
    """Bounded read-only collection from an injected QoS source (HC19).

    ``reader`` is an object with ``read(request: dict) -> dict`` returning a ``nmas.troubleshooting.qos-source/1`` document (optionally ``.provenance()``).  The collector
    issues no device command (STATE_SNAPSHOT); there is no default reader.  Every refusal becomes a missing record bound to the engine key ``qos.state``."""

    name = "qos-source"
    source_type = SourceType.STATE_SNAPSHOT

    def collect(self, target: Target, requests: Iterable[dict], reader, *, transport_name: str = "qos-source") -> dict:
        run, admission = self._run(target, transport_name)
        requests = list(requests)[:1]
        run.requested = len(requests)
        run.commands.extend("qos-state read" for _ in requests)
        if not admission.ok:
            return _refuse(run, admission, run.commands[0] if run.commands else "qos-state read")
        for req, shown in zip(requests, run.commands):
            request = {"vrf": str(req.get("vrf") or "default"), "directions": list(req.get("directions") or ["in", "out"]), "flow": dict(req.get("flow") or {})}
            started = run.now()
            try:
                run.tracker.before_request()
                doc = reader.read(dict(request, device=target.device, platform=target.canonical_platform, os_version=target.os_version))
            except PermissionDenied:
                self._fail(run, Missing.PERMISSION_DENIED, "QoS source denied access", shown)
                continue
            except (TimeoutError, TransportError, OSError):
                self._fail(run, Missing.TRANSPORT_ERROR, "QoS source unavailable", shown)
                continue
            except BudgetExceeded as exc:
                self._fail(run, Missing.BUDGET_EXCEEDED, exc.which, shown)
                break
            raw = json.dumps(doc, sort_keys=True, default=str)
            prov = getattr(reader, "provenance", None)
            gw = prov() if callable(prov) else None
            if gw and run.gateway is None:
                run.gateway = gw
            try:
                run.tracker.add_bytes(len(raw.encode("utf-8", "replace")))
            except BudgetExceeded:
                self._fail(run, Missing.OUTPUT_TOO_LARGE, "QoS document exceeds the byte budget", shown)
                continue
            evidence = build_evidence(seq=run.next_seq(), source_type=self.source_type, transport=transport_name, adapter=self.adapter, device=target.device,
                                      platform=target.platform, os_version=target.os_version, command_or_api=shown, raw=raw, started_at=started, finished_at=run.now(),
                                      status="OK", store=self.raw_store, evidence_class=EvidenceClass.OPERATIONAL, parser=dict(nz.QOS_PARSER), gateway=gw)
            run.evidence.append(evidence)
            res = nz.normalize_qos_state(doc, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, request=request, now=run.now())
            run.observations.extend(res["observations"])
            run.missing.extend(res["missing"])
        return run.bundle()


class PhysicalCollector(_BaseCollector):
    """Bounded read-only collection from an injected physical-state source (transceiver/DOM/FEC/framing counters/L1 events).

    ``reader.read(request)`` returns a ``nmas.troubleshooting.physical-source/1`` document (optionally ``.provenance()``).  One read per call, no device command (STATE_SNAPSHOT),
    no default reader.  Every refusal/failure is a missing record bound to the engine keys and interface subjects of the request."""

    name = "physical-source"
    source_type = SourceType.STATE_SNAPSHOT

    def _gap(self, run: _Run, reason: str, detail: str, shown: str, interfaces) -> None:
        for ifn in interfaces or [""]:
            for key in nz.PHY_ENGINE_KEYS:
                run.missing.append(missing_record(reason, source_type=run.source_type, device=run.target.device, detail=detail, command=shown, observed_at=run.now(),
                                                  extra={"engine_key": key, **({"subject": ifn} if ifn else {})}))

    def collect(self, target: Target, requests: Iterable[dict], reader, *, transport_name: str = "physical-source") -> dict:
        run, admission = self._run(target, transport_name)
        requests = list(requests)[:1]
        run.requested = len(requests)
        run.commands.extend("physical-state read" for _ in requests)
        if not admission.ok:
            return _refuse(run, admission, run.commands[0] if run.commands else "physical-state read")
        for req, shown in zip(requests, run.commands):
            ifs = [str(i) for i in (req.get("interfaces") or [])][:nz.PHY_MAX_INTERFACES]
            request = {"interfaces": ifs, "include": list(req.get("include") or ["optics", "fec", "counters", "events"]), "window_s": req.get("window_s")}
            started = run.now()
            try:
                run.tracker.before_request()
                doc = reader.read(dict(request, device=target.device, platform=target.canonical_platform, os_version=target.os_version))
            except PermissionDenied:
                self._gap(run, Missing.PERMISSION_DENIED, "physical source denied access", shown, ifs)
                continue
            except (TimeoutError, TransportError, OSError):
                self._gap(run, Missing.TRANSPORT_ERROR, "physical source unavailable", shown, ifs)
                continue
            except BudgetExceeded as exc:
                self._gap(run, Missing.BUDGET_EXCEEDED, exc.which, shown, ifs)
                break
            raw = json.dumps(doc, sort_keys=True, default=str)
            prov = getattr(reader, "provenance", None)
            gw = prov() if callable(prov) else None
            if gw and run.gateway is None:
                run.gateway = gw
            try:
                run.tracker.add_bytes(len(raw.encode("utf-8", "replace")))
            except BudgetExceeded:
                self._gap(run, Missing.OUTPUT_TOO_LARGE, "physical document exceeds the byte budget", shown, ifs)
                continue
            evidence = build_evidence(seq=run.next_seq(), source_type=self.source_type, transport=transport_name, adapter=self.adapter, device=target.device,
                                      platform=target.platform, os_version=target.os_version, command_or_api=shown, raw=raw, started_at=started, finished_at=run.now(),
                                      status="OK", store=self.raw_store, evidence_class=EvidenceClass.OPERATIONAL, parser=dict(nz.PHY_PARSER), gateway=gw)
            run.evidence.append(evidence)
            res = nz.normalize_physical_state(doc, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, request=request, now=run.now())
            run.observations.extend(res["observations"])
            run.missing.extend(res["missing"])
        return run.bundle()


class ProtocolCollector(_BaseCollector):
    """Bounded read-only collection from an injected routing-protocol source (capability, adjacency configuration, neighbor state).

    ``reader.read(request)`` returns a ``nmas.troubleshooting.protocol-source/1`` document (optionally ``.provenance()``).  One read per call, no device command (STATE_SNAPSHOT),
    no default reader.  The document is scrubbed of secret-bearing fields BEFORE it is stored as raw evidence or parsed; every refusal/failure is a missing record bound to the
    engine keys (and subjects) of the request."""

    name = "protocol-source"
    source_type = SourceType.STATE_SNAPSHOT

    def _gap(self, run: _Run, reason: str, detail: str, shown: str, req: dict) -> None:
        proto, peer = str(req.get("protocol") or "").lower(), str(req.get("peer") or "")
        inc = set(req.get("include") or ("capability", "config", "neighbor"))
        for key, name, subject in (("capability.protocol", "capability", proto), ("protocol.config", "config", proto), ("routing.neighbor.detail", "neighbor", peer)):
            if name in inc:
                run.missing.append(missing_record(reason, source_type=run.source_type, device=run.target.device, detail=detail, command=shown, observed_at=run.now(),
                                                  extra={"engine_key": key, **({"subject": subject} if subject else {})}))

    def collect(self, target: Target, requests: Iterable[dict], reader, *, transport_name: str = "protocol-source") -> dict:
        run, admission = self._run(target, transport_name)
        requests = list(requests)[:1]
        run.requested = len(requests)
        run.commands.extend("protocol-state read" for _ in requests)
        if not admission.ok:
            return _refuse(run, admission, run.commands[0] if run.commands else "protocol-state read")
        for req, shown in zip(requests, run.commands):
            request = {"protocol": str(req.get("protocol") or "").lower(), "af": str(req.get("af") or "").lower(), "vrf": str(req.get("vrf") or ""),
                       "interface": req.get("interface") or None, "peer": str(req.get("peer") or ""),
                       "include": [str(i) for i in (req.get("include") or ["capability", "config", "neighbor"])][:3]}
            started = run.now()
            try:
                run.tracker.before_request()
                doc = reader.read(dict(request, device=target.device, platform=target.canonical_platform, os_version=target.os_version))
            except PermissionDenied:
                self._gap(run, Missing.PERMISSION_DENIED, "protocol source denied access", shown, request)
                continue
            except (TimeoutError, TransportError, OSError):
                self._gap(run, Missing.TRANSPORT_ERROR, "protocol source unavailable", shown, request)
                continue
            except BudgetExceeded as exc:
                self._gap(run, Missing.BUDGET_EXCEEDED, exc.which, shown, request)
                break
            doc, redactions = nz.scrub_protocol_secrets(doc)          # secrets never reach the raw store, the parser or a log
            raw = json.dumps(doc, sort_keys=True, default=str)
            prov = getattr(reader, "provenance", None)
            gw = prov() if callable(prov) else None
            if gw and run.gateway is None:
                run.gateway = gw
            try:
                run.tracker.add_bytes(len(raw.encode("utf-8", "replace")))
            except BudgetExceeded:
                self._gap(run, Missing.OUTPUT_TOO_LARGE, "protocol document exceeds the byte budget", shown, request)
                continue
            evidence = build_evidence(seq=run.next_seq(), source_type=self.source_type, transport=transport_name, adapter=self.adapter, device=target.device,
                                      platform=target.platform, os_version=target.os_version, command_or_api=shown, raw=raw, started_at=started, finished_at=run.now(),
                                      status="OK", store=self.raw_store, evidence_class=EvidenceClass.OPERATIONAL, parser=dict(nz.PROTO_PARSER), gateway=gw)
            run.evidence.append(evidence)
            res = nz.normalize_protocol_state(doc, platform=target.platform, os_version=target.os_version, device=target.device, evidence=evidence, request=request, now=run.now())
            if redactions:
                for o in res["observations"]:
                    o["flags"] = list(dict.fromkeys(list(o.get("flags", [])) + ["SECRETS_REDACTED"]))
            run.observations.extend(res["observations"])
            run.missing.extend(res["missing"])
        return run.bundle()
