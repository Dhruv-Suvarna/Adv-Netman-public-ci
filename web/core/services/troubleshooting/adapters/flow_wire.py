"""NetFlow v9 / IPFIX (RFC 3954 / RFC 7011) wire decoding feeding the existing ``collectors.FlowCollector``.

This module only DECODES datagrams handed to it.  It opens no socket, binds no port and configures no exporter: a deployment-owned
receiver (outside this task) passes ``(bytes, exporter_address)`` to :meth:`FlowWireInput.ingest`.  Storage, scoping, sampling
scaling and evidence are NOT reimplemented: decoded flows are plain dicts in the record contract that
``normalization.normalize_flow_records`` already consumes (``src,dst,sport,dport,proto,bytes,packets,first,last,exporter,sampling_rate``)
and :meth:`FlowWireInput.collect` hands them to ``FlowCollector.collect`` so evidence/observations/budgets come from there.

Properties (each asserted in ``tests/test_troubleshooting_flow_wire.py``; spec UT-017, UT-022, UT-023):

* **Scoped templates** -- templates and sampling state are keyed by ``(exporter address, observation domain / source id)``; the same
  template id from two exporters or two domains never mixes.  Template ids < 256 are rejected.
* **Template lifecycle** -- re-announcement refreshes; a changed definition replaces (``TEMPLATE_CHANGED``); IPFIX withdrawal removes;
  a template older than ``template_ttl_s`` is expired (``TEMPLATE_EXPIRED``) and its data is dropped, not guessed; a v9 sysUptime
  regression or an IPFIX sequence reset flushes the domain (``EXPORTER_RESTART``).  Data for a template never seen is counted
  (``UNKNOWN_TEMPLATE``) -- it is NOT buffered, so those flows are lost, and they are reported as such.
* **Sequence accounting** -- v9 counts export packets, IPFIX counts data records; gaps are counted as ``SEQUENCE_GAP`` with the lost
  amount, duplicate/reordered datagrams are discarded and counted (cannot be told apart on UDP).
* **Sampling uncertainty** -- the rate comes from (in order) an inline samplingInterval field, an options-template/option-data record
  of the same exporter+domain, the operator-configured per-exporter default, else ``None`` (the normalizer then refuses to scale).
  Conflicting advertised rates are ``None`` too.  Every record names its ``sampling_source``.
* **Bounds** -- datagram size, sets/datagram, records/datagram, fields/template, templates/domain, exporter-domains, event log and
  pending-record queue are all capped; overflow is rejected AND counted, never silent (backpressure).  Allocation is bounded by the
  datagram size: no declared length is ever used to allocate.
* **Malformed input** -- bad version, truncated header, set/length underflow or overrun, zero-length records, undersized fields: a
  structured event and a counter; nothing is raised to the receiver.
* **Privacy** -- ``collect`` filters by the service selector on full addresses in memory, then (default ``privacy='prefix'``) masks
  src/dst to /24 (/64) BEFORE the records reach the collector, so the raw evidence blob stores no host addresses.  A selector prefix
  narrower than the mask is widened for the collector (reported in ``wire_ingest.selector_widened``).  Payload bytes are never kept.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

from .. import normalization as nz

WIRE_SCHEMA = "nmas.troubleshooting.flow-wire-decode/1"
FLOW_WIRE_VERSION = "1.0.0"
U32 = 0xFFFFFFFF

# Information elements decoded (same numbers in NetFlow v9 and IPFIX unless noted).  Everything else is skipped by length.
IE_OCTETS, IE_PACKETS, IE_PROTO = 1, 2, 4
IE_SPORT, IE_SRC4, IE_DPORT, IE_DST4 = 7, 8, 11, 12
IE_LAST_SWITCHED, IE_FIRST_SWITCHED = 21, 22          # sysUpTime based
IE_SRC6, IE_DST6 = 27, 28
IE_SAMPLING_INTERVAL = 34
IE_SAMPLER_RANDOM_INTERVAL = 50                       # v9 FLOW_SAMPLER option
IE_OCTET_TOTAL, IE_PACKET_TOTAL = 85, 86
IE_SYSTEM_INIT_MS = 160
IE_START_S, IE_END_S, IE_START_MS, IE_END_MS = 150, 151, 152, 153
IE_PKT_INTERVAL, IE_PKT_SPACE = 305, 306              # samplingPacketInterval / Space (IPFIX)
INT_IES = {IE_OCTETS, IE_PACKETS, IE_PROTO, IE_SPORT, IE_DPORT, IE_LAST_SWITCHED, IE_FIRST_SWITCHED, IE_SAMPLING_INTERVAL, IE_SAMPLER_RANDOM_INTERVAL,
           IE_OCTET_TOTAL, IE_PACKET_TOTAL, IE_SYSTEM_INIT_MS, IE_START_S, IE_END_S, IE_START_MS, IE_END_MS, IE_PKT_INTERVAL, IE_PKT_SPACE}
SAMPLING_IES = {IE_SAMPLING_INTERVAL, IE_SAMPLER_RANDOM_INTERVAL, IE_PKT_INTERVAL, IE_PKT_SPACE}
SUPPORTED_FIELDS = {
    IE_OCTETS: "octetDeltaCount", IE_PACKETS: "packetDeltaCount", IE_PROTO: "protocolIdentifier", IE_SPORT: "sourceTransportPort",
    IE_SRC4: "sourceIPv4Address", IE_DPORT: "destinationTransportPort", IE_DST4: "destinationIPv4Address", IE_SRC6: "sourceIPv6Address",
    IE_DST6: "destinationIPv6Address", IE_LAST_SWITCHED: "flowEndSysUpTime", IE_FIRST_SWITCHED: "flowStartSysUpTime", IE_OCTET_TOTAL: "octetTotalCount",
    IE_PACKET_TOTAL: "packetTotalCount", IE_SAMPLING_INTERVAL: "samplingInterval", IE_SAMPLER_RANDOM_INTERVAL: "samplerRandomInterval",
    IE_PKT_INTERVAL: "samplingPacketInterval", IE_PKT_SPACE: "samplingPacketSpace", IE_SYSTEM_INIT_MS: "systemInitTimeMilliseconds",
    IE_START_S: "flowStartSeconds", IE_END_S: "flowEndSeconds", IE_START_MS: "flowStartMilliseconds", IE_END_MS: "flowEndMilliseconds"}


class Event:
    """Stable event/issue codes (also counter keys)."""
    BAD_VERSION = "BAD_VERSION"
    TRUNCATED_HEADER = "TRUNCATED_HEADER"
    OVERSIZE_DATAGRAM = "OVERSIZE_DATAGRAM"
    LENGTH_MISMATCH = "LENGTH_MISMATCH"
    MALFORMED_SET = "MALFORMED_SET"
    MALFORMED_TEMPLATE = "MALFORMED_TEMPLATE"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    TOO_MANY_SETS = "TOO_MANY_SETS"
    TOO_MANY_RECORDS = "TOO_MANY_RECORDS"
    TEMPLATE_LIMIT = "TEMPLATE_LIMIT"
    TEMPLATE_CHANGED = "TEMPLATE_CHANGED"
    TEMPLATE_WITHDRAWN = "TEMPLATE_WITHDRAWN"
    TEMPLATE_EXPIRED = "TEMPLATE_EXPIRED"
    UNKNOWN_TEMPLATE = "UNKNOWN_TEMPLATE"
    INCOMPLETE_RECORD = "INCOMPLETE_RECORD"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    DUPLICATE_OR_REORDERED = "DUPLICATE_OR_REORDERED_DISCARDED"
    EXPORTER_RESTART = "EXPORTER_RESTART"
    UNKNOWN_EXPORTER = "UNKNOWN_EXPORTER"
    EXPORTER_LIMIT = "EXPORTER_LIMIT"
    BACKPRESSURE = "DROPPED_BACKPRESSURE"
    SAMPLING_CONFLICT = "SAMPLING_CONFLICT"
    OPTIONS_IGNORED = "OPTIONS_IGNORED"


# Loss that makes volume estimates unreliable (propagated as DATA_LOSS).
LOSS_EVENTS = frozenset({Event.UNKNOWN_TEMPLATE, Event.TEMPLATE_EXPIRED, Event.SEQUENCE_GAP, Event.BACKPRESSURE, Event.MALFORMED_SET, Event.MALFORMED_RECORD,
                         Event.TOO_MANY_RECORDS, Event.TOO_MANY_SETS, Event.DUPLICATE_OR_REORDERED, Event.INCOMPLETE_RECORD, Event.LENGTH_MISMATCH,
                         Event.EXPORTER_RESTART})


@dataclass(frozen=True)
class WireConfig:
    max_datagram_bytes: int = 9216
    max_sets_per_datagram: int = 64
    max_records_per_datagram: int = 1024
    max_fields_per_template: int = 64
    max_templates_per_domain: int = 64
    max_exporter_domains: int = 256
    max_events_per_datagram: int = 32
    max_pending_records: int = 50_000
    template_ttl_s: float = 1800.0
    restart_seq_max: int = 256                  # IPFIX: backward jump landing at or below this is treated as an exporter restart
    require_known_exporter: bool = True
    default_sampling: dict = field(default_factory=dict)    # exporter device name -> operator-asserted 1-in-N

    def as_dict(self) -> dict:
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in self.__dict__.items()}


@dataclass
class _Template:
    tid: int
    fields: tuple          # ((ie, length, enterprise), ...) ; length 0xFFFF == variable
    scope_count: int       # >0 for options templates
    learned_at: datetime
    options: bool = False

    def signature(self) -> tuple:
        return (self.fields, self.scope_count, self.options)

    def min_length(self) -> int:
        return sum(1 if ln == 0xFFFF else ln for _, ln, _ in self.fields)


@dataclass
class _Domain:
    templates: dict = field(default_factory=dict)
    expected_seq: int | None = None
    last_uptime: int | None = None
    sampling: dict = field(default_factory=dict)      # sampler/selector key -> rate
    sampling_conflict: bool = False
    datagrams: int = 0


class _Reader:
    """Bounds-checked big-endian cursor over an immutable bytes object."""

    def __init__(self, data: bytes, pos: int, end: int):
        self.data, self.pos, self.end = data, pos, end

    def left(self) -> int:
        return self.end - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or n > self.left():
            raise ValueError("underflow")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]


class FlowWireDecoder:
    """Stateful per-exporter decoder.  Not thread-safe; one receiver thread should own it."""

    def __init__(self, config: WireConfig | None = None, *, clock: Callable[[], datetime] = nz.utcnow):
        self.config = config or WireConfig()
        self.clock = clock
        self.domains: dict[tuple, _Domain] = {}
        self.counters: Counter = Counter()
        self.loss: Counter = Counter()          # units lost per event code (records / export packets / datagrams)

    # -- public ---------------------------------------------------------------------------------
    def decode(self, datagram: bytes, exporter_addr: str, exporter: str | None = None, received_at: datetime | None = None) -> dict:
        """Decode ONE datagram.  Never raises on hostile input.  ``exporter`` is the device name placed into records."""
        received = nz.to_utc(received_at) if received_at is not None else self.clock()
        out = {"schema": WIRE_SCHEMA, "exporter_addr": exporter_addr, "exporter": exporter or exporter_addr, "version": None, "domain": None,
               "records": [], "events": [], "event_counts": {}, "templates_learned": 0, "data_records": 0}
        self.counters["datagrams"] += 1
        try:
            self._decode(bytes(datagram), exporter_addr, out, received)
        except Exception as exc:                     # pylint: disable=broad-exception-caught  # noqa: BLE001 - last-resort guard; a decoder bug must not take the receiver down
            self._event(out, Event.MALFORMED_SET, f"internal decode error {type(exc).__name__}")
        return out

    def forget(self, exporter_addr: str) -> None:
        for key in [k for k in self.domains if k[0] == exporter_addr]:
            del self.domains[key]

    def template_summary(self) -> list[dict]:
        return [{"exporter_addr": k[0], "domain": k[1], "templates": sorted(d.templates), "expected_seq": d.expected_seq} for k, d in sorted(self.domains.items(), key=str)]

    # -- internals ------------------------------------------------------------------------------
    def _event(self, out: dict, code: str, detail: str, count: int = 1, **extra) -> None:
        self.counters[code] += count
        if code in LOSS_EVENTS:
            self.loss[code] += count
        out["event_counts"][code] = out["event_counts"].get(code, 0) + count
        if len(out["events"]) < self.config.max_events_per_datagram:
            out["events"].append({"code": code, "detail": detail, "count": count, **extra})
        elif len(out["events"]) == self.config.max_events_per_datagram:
            out["events"].append({"code": "EVENTS_TRUNCATED", "detail": "further events counted in event_counts only", "count": 0})

    def _decode(self, data: bytes, addr: str, out: dict, received: datetime) -> None:
        cfg = self.config
        if len(data) > cfg.max_datagram_bytes:
            self._event(out, Event.OVERSIZE_DATAGRAM, f"{len(data)} > {cfg.max_datagram_bytes} bytes")
            return
        if len(data) < 2:
            self._event(out, Event.TRUNCATED_HEADER, "fewer than 2 bytes")
            return
        version = struct.unpack_from("!H", data)[0]
        out["version"] = version
        if version == 9:
            if len(data) < 20:
                self._event(out, Event.TRUNCATED_HEADER, "NetFlow v9 header needs 20 bytes")
                return
            _, _, uptime, unix_secs, seq, domain = struct.unpack_from("!HHIIII", data)
            body_end = len(data)
            export_dt = datetime.fromtimestamp(unix_secs, timezone.utc)
        elif version == 10:
            if len(data) < 16:
                self._event(out, Event.TRUNCATED_HEADER, "IPFIX header needs 16 bytes")
                return
            _, length, export_secs, seq, domain = struct.unpack_from("!HHIII", data)
            uptime = None
            if length < 16 or length > len(data):
                self._event(out, Event.LENGTH_MISMATCH, f"IPFIX message length {length} vs datagram {len(data)}")
                return
            if length < len(data):
                self._event(out, Event.LENGTH_MISMATCH, f"{len(data) - length} trailing byte(s) ignored")
            body_end = length
            export_dt = datetime.fromtimestamp(export_secs, timezone.utc)
        else:
            self._event(out, Event.BAD_VERSION, f"unsupported export version {version}")
            return
        out["domain"] = domain
        key = (addr, domain)
        dom = self.domains.get(key)
        if dom is None:
            if len(self.domains) >= cfg.max_exporter_domains:
                self._event(out, Event.EXPORTER_LIMIT, f"exporter/domain table full ({cfg.max_exporter_domains})")
                return
            dom = self.domains[key] = _Domain()
        dom.datagrams += 1
        if not self._sequence(out, dom, version, seq, uptime, export_dt):
            return                                  # duplicate/reordered: sets are not processed (would double count)
        reader = _Reader(data, 20 if version == 9 else 16, body_end)
        ctx = {"version": version, "domain": domain, "uptime": uptime, "export": export_dt, "received": received, "addr": addr, "seq": seq, "sysinit": None}
        sets = 0
        while reader.left() >= 4:
            sets += 1
            if sets > cfg.max_sets_per_datagram:
                self._event(out, Event.TOO_MANY_SETS, f"more than {cfg.max_sets_per_datagram} sets; remainder discarded")
                break
            set_id = reader.u16()
            set_len = reader.u16()
            if set_len < 4 or set_len - 4 > reader.left():
                self._event(out, Event.MALFORMED_SET, f"set {set_id} length {set_len} invalid ({reader.left() + 4} bytes remain); rest of datagram discarded")
                break
            body = _Reader(data, reader.pos, reader.pos + set_len - 4)
            reader.pos += set_len - 4
            tpl_ids = (0, 1) if version == 9 else (2, 3)
            if set_id in tpl_ids:
                self._templates(out, dom, body, ctx, options=(set_id == tpl_ids[1]))
            elif set_id < 256:
                self._event(out, Event.MALFORMED_SET, f"reserved set id {set_id} ignored")
            else:
                self._data(out, dom, body, set_id, ctx)
        if reader.left() and reader.left() < 4:
            pass                                    # trailing padding < one set header is legal (v9 4-byte alignment)
        if version == 10:
            dom.expected_seq = (seq + out["data_records"]) & U32

    def _sequence(self, out: dict, dom: _Domain, version: int, seq: int, uptime: int | None, export_dt: datetime) -> bool:
        if version == 9 and dom.last_uptime is not None and uptime is not None:
            wrapped = dom.last_uptime > 0xF0000000 and uptime < 0x10000000
            if uptime < dom.last_uptime and not wrapped:
                self._restart(out, dom, f"sysUptime regressed {dom.last_uptime}->{uptime}")
        if version == 9:
            dom.last_uptime = uptime
        if dom.expected_seq is not None:
            delta = (seq - dom.expected_seq) & U32
            if delta == 0:
                pass
            elif delta < 0x80000000:
                unit = "export packet(s)" if version == 9 else "data record(s)"
                self._event(out, Event.SEQUENCE_GAP, f"{delta} {unit} missing before seq {seq}", count=delta, unit=unit)
            else:
                back = (dom.expected_seq - seq) & U32
                if version == 10 and seq <= self.config.restart_seq_max and back > self.config.restart_seq_max:
                    self._restart(out, dom, f"IPFIX sequence reset {dom.expected_seq}->{seq}")
                else:
                    self._event(out, Event.DUPLICATE_OR_REORDERED, f"seq {seq} behind expected {dom.expected_seq}")
                    return False
        if version == 9:
            dom.expected_seq = (seq + 1) & U32
        return True

    def _restart(self, out: dict, dom: _Domain, why: str) -> None:
        dom.templates.clear()
        dom.sampling.clear()
        dom.sampling_conflict = False
        dom.expected_seq = None
        self._event(out, Event.EXPORTER_RESTART, why + "; templates and sampling state flushed until re-announced")

    def _templates(self, out: dict, dom: _Domain, body: _Reader, ctx: dict, *, options: bool) -> None:
        ipfix = ctx["version"] == 10
        while body.left() >= 4:
            try:
                tid = body.u16()
                if options:
                    if ipfix:
                        count, scope = body.u16(), body.u16()
                        if scope > count or (count and scope == 0):
                            raise ValueError("bad scope field count")
                        specs = count
                    else:
                        scope_len, opt_len = body.u16(), body.u16()
                        if scope_len % 4 or opt_len % 4:
                            raise ValueError("v9 option lengths not multiples of 4")
                        scope, specs = scope_len // 4, (scope_len + opt_len) // 4
                else:
                    specs, scope = body.u16(), 0
                if specs > self.config.max_fields_per_template:
                    raise ValueError(f"{specs} fields exceeds {self.config.max_fields_per_template}")
                fields = []
                for _ in range(specs):
                    ie, length = body.u16(), body.u16()
                    ent = 0
                    if ipfix and ie & 0x8000:
                        ie &= 0x7FFF
                        ent = struct.unpack("!I", body.take(4))[0]
                    if length == 0 or (length == 0xFFFF and not ipfix):
                        raise ValueError(f"field {ie} has invalid length {length}")
                    fields.append((ie, length, ent))
            except ValueError as exc:
                self._event(out, Event.MALFORMED_TEMPLATE, f"template record rejected: {exc}; rest of set discarded")
                return
            if tid < 256:
                self._event(out, Event.MALFORMED_TEMPLATE, f"template id {tid} < 256 rejected")
                continue
            if not fields:
                if ipfix and dom.templates.pop(tid, None) is not None:
                    self._event(out, Event.TEMPLATE_WITHDRAWN, f"template {tid} withdrawn by exporter")
                continue
            tpl = _Template(tid, tuple(fields), scope, ctx["received"], options)
            if tpl.min_length() == 0:
                self._event(out, Event.MALFORMED_TEMPLATE, f"template {tid} has zero-length records")
                continue
            old = dom.templates.get(tid)
            if old is None and len(dom.templates) >= self.config.max_templates_per_domain:
                self._event(out, Event.TEMPLATE_LIMIT, f"template table full ({self.config.max_templates_per_domain}); template {tid} not stored")
                continue
            if old is not None and old.signature() != tpl.signature():
                self._event(out, Event.TEMPLATE_CHANGED, f"template {tid} redefined; earlier definition replaced")
            dom.templates[tid] = tpl
            out["templates_learned"] += 1
            self.counters["templates_learned"] += 1

    def _data(self, out: dict, dom: _Domain, body: _Reader, set_id: int, ctx: dict) -> None:
        cfg = self.config
        tpl = dom.templates.get(set_id)
        if tpl is None:
            self._event(out, Event.UNKNOWN_TEMPLATE, f"data set {set_id} has no template for this exporter/domain (flows lost, not buffered)", template_id=set_id,
                               count=1, approx_bytes=body.left())
            return
        age = (ctx["received"] - tpl.learned_at).total_seconds()
        if age > cfg.template_ttl_s:
            del dom.templates[set_id]
            self._event(out, Event.TEMPLATE_EXPIRED, f"template {set_id} not refreshed for {age:.0f}s > {cfg.template_ttl_s:.0f}s; removed", template_id=set_id)
            return
        minlen = tpl.min_length()
        while body.left() >= minlen:
            if out["data_records"] >= cfg.max_records_per_datagram:
                self._event(out, Event.TOO_MANY_RECORDS, f"more than {cfg.max_records_per_datagram} records in one datagram; remainder discarded")
                return
            try:
                values = self._record(body, tpl)
            except ValueError as exc:
                self._event(out, Event.MALFORMED_RECORD, f"template {set_id}: {exc}; rest of set discarded", template_id=set_id)
                return
            out["data_records"] += 1
            if tpl.options:
                self._options(out, dom, tpl, values)
                continue
            rec = self._flow(out, dom, tpl, values, ctx)
            if rec is not None:
                out["records"].append(rec)
        # leftover < one record is padding (RFC 7011 3.3.1 / RFC 3954 5.1)

    @staticmethod
    def _record(body: _Reader, tpl: _Template) -> dict:
        values: dict[Any, Any] = {}
        scope_raw = b""
        for n, (ie, length, ent) in enumerate(tpl.fields):
            if length == 0xFFFF:
                first = body.take(1)[0]
                length = struct.unpack("!H", body.take(2))[0] if first == 255 else first
            raw = body.take(length)
            if n < tpl.scope_count:
                scope_raw += raw
            if ent:
                continue
            if ie in INT_IES:
                if length > 8:
                    raise ValueError(f"integer field {ie} length {length} > 8")
                values[ie] = int.from_bytes(raw, "big")
            elif ie in (IE_SRC4, IE_DST4):
                if length != 4:
                    raise ValueError(f"IPv4 field {ie} length {length}")
                values[ie] = str(ipaddress.IPv4Address(raw))
            elif ie in (IE_SRC6, IE_DST6):
                if length != 16:
                    raise ValueError(f"IPv6 field {ie} length {length}")
                values[ie] = str(ipaddress.IPv6Address(raw))
        values["scope"] = scope_raw
        return values

    def _options(self, out: dict, dom: _Domain, tpl: _Template, values: dict) -> None:
        rate = None
        if IE_PKT_INTERVAL in values and values[IE_PKT_INTERVAL] > 0:
            rate = (values[IE_PKT_INTERVAL] + values.get(IE_PKT_SPACE, 0)) / values[IE_PKT_INTERVAL]
        else:
            for ie in (IE_SAMPLING_INTERVAL, IE_SAMPLER_RANDOM_INTERVAL):
                if values.get(ie, 0) > 0:
                    rate = values[ie]
                    break
        if rate is None:
            self._event(out, Event.OPTIONS_IGNORED, f"options template {tpl.tid} carries no supported sampling field")
            return
        rate = int(rate) if float(rate).is_integer() else None
        if rate is None:
            dom.sampling_conflict = True
            self._event(out, Event.SAMPLING_CONFLICT, "non-integral sampling ratio ignored")
            return
        dom.sampling[(tpl.tid, values.get("scope", b""))] = rate
        if len(set(dom.sampling.values())) > 1:
            dom.sampling_conflict = True
            self._event(out, Event.SAMPLING_CONFLICT, f"conflicting advertised sampling rates {sorted(set(dom.sampling.values()))}: no rate asserted")

    def _flow(self, out: dict, dom: _Domain, tpl: _Template, v: dict, ctx: dict) -> dict | None:
        src = v.get(IE_SRC4) or v.get(IE_SRC6)
        dst = v.get(IE_DST4) or v.get(IE_DST6)
        octets = v.get(IE_OCTETS, v.get(IE_OCTET_TOTAL))
        packets = v.get(IE_PACKETS, v.get(IE_PACKET_TOTAL))
        missing = [n for n, x in (("src", src), ("dst", dst), ("proto", v.get(IE_PROTO)), ("bytes", octets)) if x is None]
        if missing:
            self._event(out, Event.INCOMPLETE_RECORD, f"template {tpl.tid} record lacks {','.join(missing)}; dropped", template_id=tpl.tid)
            return None
        flags, sampling_source = [], "unknown"
        rate = None
        inline = next((v[i] for i in (IE_SAMPLING_INTERVAL, IE_SAMPLER_RANDOM_INTERVAL) if v.get(i, 0) > 0), None)
        advertised = set(dom.sampling.values())
        if inline is not None:
            rate, sampling_source = inline, "record"
        elif advertised and not dom.sampling_conflict:
            rate, sampling_source = next(iter(advertised)), "options"
        elif dom.sampling_conflict:
            flags.append("SAMPLING_CONFLICT")
        if rate is None and not dom.sampling_conflict:
            rate_cfg = self.config.default_sampling.get(out["exporter"])
            if isinstance(rate_cfg, int) and rate_cfg >= 1:
                rate, sampling_source = rate_cfg, "configured"
        if rate is None:
            flags.append("SAMPLING_RATE_UNKNOWN")
        first, last, tsrc = self._times(v, ctx)
        if tsrc == "export_time":
            flags.append("TIMESTAMP_FROM_EXPORT_TIME")
        if packets is None:
            packets = 0
            flags.append("PACKETS_MISSING")
        return {"src": src, "dst": dst, "sport": v.get(IE_SPORT), "dport": v.get(IE_DPORT), "proto": v[IE_PROTO], "bytes": octets, "packets": packets,
                "first": nz.iso(first), "last": nz.iso(last), "exporter": out["exporter"], "sampling_rate": rate, "sampling_source": sampling_source,
                "wire": {"version": ctx["version"], "domain": ctx["domain"], "template_id": tpl.tid, "time_source": tsrc, "flags": flags}}

    @staticmethod
    def _times(v: dict, ctx: dict) -> tuple[datetime, datetime, str]:
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        try:
            if IE_END_MS in v:
                last = epoch + timedelta(milliseconds=v[IE_END_MS])
                return (epoch + timedelta(milliseconds=v[IE_START_MS]) if IE_START_MS in v else last), last, "flowEndMilliseconds"
            if IE_END_S in v:
                last = epoch + timedelta(seconds=v[IE_END_S])
                return (epoch + timedelta(seconds=v[IE_START_S]) if IE_START_S in v else last), last, "flowEndSeconds"
            if IE_LAST_SWITCHED in v and ctx["uptime"] is not None:      # v9: uptime-relative milliseconds
                def conv(ms: int) -> datetime:
                    return ctx["export"] - timedelta(milliseconds=(ctx["uptime"] - ms) & U32)
                last = conv(v[IE_LAST_SWITCHED])
                return (conv(v[IE_FIRST_SWITCHED]) if IE_FIRST_SWITCHED in v else last), last, "sysUpTime"
        except (OverflowError, ValueError):
            pass
        return ctx["export"], ctx["export"], "export_time"


# --------------------------------------------------------------------------------------------------------------------
# Input adapter: queue + backpressure + FlowCollector bridge
# --------------------------------------------------------------------------------------------------------------------
def _widen(prefixes: Iterable[str], privacy: str) -> tuple[list[str], bool]:
    out, widened = [], False
    for p in prefixes:
        net = ipaddress.ip_network(p, strict=False)
        limit = 24 if net.version == 4 else 64
        if privacy == "prefix" and net.prefixlen > limit:
            net, widened = net.supernet(new_prefix=limit), True
        out.append(str(net))
    return out, widened


class FlowWireInput:
    """Configurable input adapter.  ``exporters`` maps exporter source address -> device name (the NMAS inventory name)."""

    def __init__(self, exporters: dict[str, str] | None = None, config: WireConfig | None = None, *, clock: Callable[[], datetime] = nz.utcnow):
        self.config = config or WireConfig()
        self.exporters = dict(exporters or {})
        self.decoder = FlowWireDecoder(self.config, clock=clock)
        self.queue: deque = deque()
        self.recent_events: deque = deque(maxlen=100)
        self.stats: Counter = Counter()
        self.unknown_exporters: Counter = Counter()

    def ingest(self, datagram: bytes, exporter_addr: str, received_at: datetime | None = None) -> dict:
        """Decode and queue one datagram.  Returns the decode summary WITHOUT records (records live in the bounded queue)."""
        device = self.exporters.get(exporter_addr)
        if device is None and self.config.require_known_exporter:
            self.stats[Event.UNKNOWN_EXPORTER] += 1
            if len(self.unknown_exporters) < 32 or exporter_addr in self.unknown_exporters:
                self.unknown_exporters[exporter_addr] += 1
            return {"schema": WIRE_SCHEMA, "exporter_addr": exporter_addr, "accepted": False, "records": 0,
                    "events": [{"code": Event.UNKNOWN_EXPORTER, "detail": "datagram from an exporter not in the configured map was discarded", "count": 1}]}
        res = self.decoder.decode(datagram, exporter_addr, device, received_at)
        queued = dropped = 0
        for rec in res["records"]:
            if len(self.queue) >= self.config.max_pending_records:
                dropped += 1
                continue
            self.queue.append(rec)
            queued += 1
        if dropped:
            self.decoder._event(res, Event.BACKPRESSURE, f"{dropped} decoded record(s) rejected: pending queue full ({self.config.max_pending_records})", count=dropped)
        self.stats["records_queued"] += queued
        for ev in res["events"]:
            self.recent_events.append({"exporter": device or exporter_addr, **ev})
        summary = {k: v for k, v in res.items() if k != "records"}
        summary.update(accepted=True, records=queued, dropped_backpressure=dropped)
        return summary

    def ingest_many(self, datagrams: Iterable[tuple], *, max_datagrams: int = 10_000) -> dict:
        """Bounded batch: ``(bytes, addr[, received_at])`` tuples; at most ``max_datagrams`` are processed, the rest are counted as not processed."""
        done = skipped = 0
        for item in datagrams:
            if done >= max_datagrams:
                skipped += 1
                continue
            self.ingest(*item)
            done += 1
        if skipped:
            self.stats["datagrams_not_processed"] += skipped
        return {"processed": done, "not_processed": skipped}

    def drain(self, *, exporter: str | None = None, limit: int | None = None) -> list[dict]:
        keep: deque = deque()
        taken: list[dict] = []
        while self.queue:
            rec = self.queue.popleft()
            if (exporter is None or rec["exporter"] == exporter) and (limit is None or len(taken) < limit):
                taken.append(rec)
            else:
                keep.append(rec)
        self.queue = keep
        return taken

    def health(self) -> dict:
        """Wire-level loss ledger.  ``data_loss`` is True when any counted event makes volume figures lower bounds."""
        loss = dict(self.decoder.loss)
        loss.update({k: v for k, v in ((Event.BACKPRESSURE, self.stats.get(Event.BACKPRESSURE, 0)),) if v})
        return {"schema": "nmas.troubleshooting.flow-wire-health/1", "decoder_version": FLOW_WIRE_VERSION, "datagrams": self.decoder.counters["datagrams"],
                "records_queued": self.stats["records_queued"], "pending": len(self.queue), "counters": dict(self.decoder.counters), "loss": loss,
                "unknown_exporters": dict(self.unknown_exporters), "datagrams_not_processed": self.stats["datagrams_not_processed"],
                "data_loss": bool(loss or self.unknown_exporters or self.stats["datagrams_not_processed"]),
                "templates": self.decoder.template_summary(), "recent_events": list(self.recent_events)[-20:]}

    def collect(self, collector, target, selector: dict, *, expected_exporters: Iterable[str] = (), privacy: str = "prefix", limit: int | None = None,
                transport_name: str = "netflow-ipfix-wire") -> dict:
        """Drain this target's records through ``FlowCollector.collect``.  Records of other exporters stay queued.

        Selector matching runs here on full addresses; for ``privacy='prefix'`` addresses are masked afterwards, so the collector's raw
        evidence never holds host addresses."""
        records = self.drain(exporter=target.device, limit=limit)
        scoped = [r for r in records if nz.flow_matches(r, selector)]
        out_of_scope = len(records) - len(scoped)
        eff = dict(selector)
        widened = False
        for key in ("src_prefixes", "dst_prefixes"):
            if selector.get(key):
                eff[key], w = _widen(selector[key], privacy)
                widened = widened or w
        if privacy == "prefix":
            scoped = [dict(r, src=nz._mask_host(r["src"]).split("/")[0], dst=nz._mask_host(r["dst"]).split("/")[0]) for r in scoped]
        bundle = collector.collect(target, scoped, eff, expected_exporters=expected_exporters, privacy=privacy, transport_name=transport_name)
        health = self.health()
        bundle["wire_ingest"] = {"decoder_version": FLOW_WIRE_VERSION, "records_drained": len(records), "out_of_scope_prefiltered": out_of_scope,
                                 "selector_widened": widened, "privacy": privacy, "health": {k: health[k] for k in ("loss", "data_loss", "counters", "unknown_exporters")}}
        if health["data_loss"] and isinstance(bundle.get("run"), dict) and isinstance(bundle["run"].get("flags"), list):
            if "WIRE_DATA_LOSS" not in bundle["run"]["flags"]:
                bundle["run"]["flags"].append("WIRE_DATA_LOSS")
        return bundle
