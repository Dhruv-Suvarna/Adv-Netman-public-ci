"""Active-probe source adapter: bounded TCP connect (``service.probe``, HC22) and path trace (``path.trace``, HC17) through an INJECTED runner.

Flow: ``runtime.CollectorProvider`` -> ``requests_for_device`` / ``policy_for`` (this module; derives requests ONLY from the case flow tuple, never invents a
destination) -> ``collectors.ProbeCollector`` (authorization, scope, capability and budget gate; calls the injected runner) -> ``parse_response`` (this module,
parsers ``probe.tcp`` / ``probe.trace``) -> ``runtime.map_observations`` -> engine keys ``service.probe@tcp`` and ``path.trace@<dst>``.

``pmtu_probe`` (``path.pmtu``, HC21/RB06) sends a bounded ladder of DF ICMP/UDP probes of stated PAYLOAD sizes (packet size reported separately); requires the case
authorization to list ``pmtu_probe`` and is bounded in packets, bytes, rate and time.  Untested sizes / invisible PTB stay UNKNOWN.

Nothing here opens a socket, runs a shell or a CLI command, and there is NO default runner: without a deployment-supplied runner AND an explicit active-probe
authorization every probe key is an explicit ``NOT_CONFIGURED`` / ``PERMISSION_DENIED`` gap (UNKNOWN), never a value.

What a result does and does not prove (carried in every value as ``limitations``):
* a TCP connect proves the SYN/SYN-ACK exchange from the actual vantage only; it proves no L7 transaction and not production-flow losslessness (``l7_verified`` is
  always False, ``production_flow_equivalent`` is always False);
* a path trace shows the forward path from the vantage only, by the stated method; ICMP/UDP traces do not prove the path of a TCP flow.
"""

from __future__ import annotations

import ipaddress
import json
import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Protocol

from .. import collectors as col
from .. import normalization as nz

SOURCE_VERSION = "1.0.0"
REQUEST_SCHEMA, RESPONSE_SCHEMA = "nmas.probe.request/1", "nmas.probe.response/1"
OPS = ("tcp_connect", "path_trace", "pmtu_probe")
TRACE_METHODS = ("tcp", "udp", "icmp")
PARSERS = {"tcp_connect": {"id": "probe.tcp", "version": "probe-json-1.0", "template": "nmas.probe.response/1", "input_kind": "json"},
           "path_trace": {"id": "probe.trace", "version": "probe-json-1.0", "template": "nmas.probe.response/1", "input_kind": "json"},
           "pmtu_probe": {"id": "probe.pmtu", "version": "probe-json-1.0", "template": "nmas.probe.response/1", "input_kind": "json"}}
LIVE, RECORDED, SIMULATED = "LIVE_GATEWAY_PINNED", "RECORDED", "SIMULATED"
OUTCOMES = ("connected", "refused", "timeout", "unreachable", "error")
HOP_STATUSES = ("ttl_exceeded", "reached", "timeout", "unreachable", "filtered")
PROBE_KEYS = ("service.probe", "path.trace", "path.pmtu")
PMTU_SCHEMA = "nmas.pmtu/1"
PMTU_PROTOCOLS = ("icmp", "udp")           # TCP is never used for size probes: actual TCP production behaviour is NOT measured by this source
PMTU_OUTCOMES = ("reply", "ptb", "timeout", "error", "local_too_big")
PTB_VISIBILITY = ("observable", "not_observable", "unknown")
L3_HEADER = {"ipv4": 20, "ipv6": 40}
L4_HEADER = {"icmp": 8, "udp": 8}          # ICMP echo header / UDP header
PMTU_LIMITATIONS = ("payload size is the L4 payload; packet size = payload + L4 header + IP header (reported separately)",
                    "ICMP/UDP DF probes do not prove TCP production behaviour (MSS clamping, TCP options, flow policy): tcp_behavior_verified is always False",
                    "a size that times out is a loss, not a PTB: a black hole needs the vantage to be able to observe ICMP errors (ptb_visibility=observable)",
                    "sizes that were not tested are UNKNOWN, never assumed to pass or to fail")
TCP_LIMITATIONS = ("TCP connect proves the SYN/SYN-ACK exchange from the stated vantage only; it does not prove an L7 transaction",
                   "probe sources/ports differ from production flows: success or loss here is not production-flow losslessness")
TRACE_LIMITATIONS = ("forward path from the stated vantage only; the return path is not observed",
                     "a silent hop is unknown (filtering/rate-limit), not a failure by itself")


class ProbeRunner(Protocol):
    """Injected, authorized.  ``execute(request_dict) -> JSON text`` for one ``nmas.probe.request/1``; ``capabilities() -> iterable of ops`` (REQUIRED, fail closed);
    optional ``provenance()`` (gateway dict).  May raise ``TimeoutError`` / ``collectors.TransportError`` / ``collectors.PermissionDenied``.  The runner must execute
    only a bounded TCP connect / TTL-limited trace from the requested source: it never receives or runs shell text."""

    def capabilities(self) -> Iterable[str]: ...

    def execute(self, request: dict): ...


@dataclass
class ProbeContext:
    """``RuntimeDeps.probe_context``.  Everything is explicit; an empty field authorizes nothing.

    ``authorization``: ``{id, case_id, expires_at(ISO), approved_by}`` -- the active-probe approval bound to ONE case and an expiry.
    ``admitted_sources``: devices allowed to originate probes.  ``destinations`` / ``ports``: authorized targets (names or IPs / TCP ports).
    ``addresses``: {name: IP} address book (the flow ``dst`` and ``src`` are looked up here unless already IP literals); its inverse names trace hops.
    ``hop_owners``: extra {IP: device} for transit interface addresses."""

    authorization: dict | None = None
    admitted_sources: tuple = ()
    destinations: tuple = ()
    ports: tuple = ()
    addresses: dict = field(default_factory=dict)
    hop_owners: dict = field(default_factory=dict)
    count: int = 3
    max_count: int = 5
    max_probes: int = 10
    trace_method: str = "tcp"
    max_hops: int = 16
    max_hops_cap: int = 30
    # --- size-dependent (PMTU) probes: every field is an explicit, bounded scope; the case authorization must additionally list "pmtu_probe" in ``operations``
    pmtu_protocol: str = "icmp"                # protocol of the requested ladder; must be in ``pmtu_protocols``
    pmtu_protocols: tuple = ()                 # authorized probe protocols (subset of PMTU_PROTOCOLS); EMPTY => size probes are not requested at all (explicit opt-in)
    pmtu_families: tuple = ("ipv4", "ipv6")    # authorized address families
    pmtu_udp_port: int = 0                     # UDP only; must also be listed in ``ports``
    pmtu_sizes: tuple = ()                     # explicit payload ladder; empty => derived ladder up to ``pmtu_required_payload``
    pmtu_required_payload: int = 0             # 0 => flow payload_bytes/app_bytes, else 1472
    pmtu_per_size: int = 2
    pmtu_max_per_size: int = 3
    pmtu_max_sizes: int = 8
    pmtu_max_payload: int = 9000
    pmtu_max_packet_bytes: int = 40_000        # total bytes on the wire per request (all trials)
    pmtu_rate_pps: int = 2
    pmtu_max_pps: int = 5
    pmtu_max_seconds: float = 30.0


def describe_source(*, gateway: dict | None = None, recorded: bool = False) -> dict:
    label = LIVE if gateway and gateway.get("live") is True else (RECORDED if recorded else SIMULATED)
    return {"source": "active_probe", "label": label, "live": label == LIVE, "parsers": {k: dict(v) for k, v in PARSERS.items()}, "gateway": gateway or None,
            "adapter_version": SOURCE_VERSION, "limitations": list(TCP_LIMITATIONS + TRACE_LIMITATIONS)}


def _ip(value) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.is_multicast or ip.is_unspecified or (ip.version == 4 and int(ip) == 0xFFFFFFFF):
        return None
    return str(ip)


def _address(name: str, ctx: ProbeContext | None) -> str | None:
    return _ip(name) or (_ip((ctx.addresses or {}).get(name)) if ctx else None)


def _port(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535 else None


def policy_for(flow: dict, case_id: str, ctx: ProbeContext | None) -> col.ProbePolicy | None:
    """The authorization/scope policy for ONE case flow, or None when no probe context exists (every probe is then a NOT_CONFIGURED gap)."""
    if ctx is None:
        return None
    auth = dict(ctx.authorization or {})
    deny = ""
    expires = None
    if not auth.get("id"):
        deny = "no active-probe authorization is recorded for this case"
    elif auth.get("case_id") != case_id:
        deny = "active-probe authorization is bound to a different case"
    else:
        try:
            expires = nz.to_utc(auth["expires_at"])
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            deny = "active-probe authorization has no valid expiry"
    return col.ProbePolicy(
        authorization_id=str(auth.get("id") or ""), expires_at=expires, deny_reason=deny, admitted_sources=tuple(map(str, ctx.admitted_sources)),
        destinations=tuple(map(str, ctx.destinations)), ports=tuple(p for p in ctx.ports if _port(p)), flow={k: flow.get(k) for k in ("src", "dst", "protocol", "port")},
        max_count=max(1, min(int(ctx.max_count), 10)), max_probes=max(1, min(int(ctx.max_probes), 50)), max_hops=max(1, min(int(ctx.max_hops_cap), 30)),
        methods=tuple(TRACE_METHODS), pmtu_authorized="pmtu_probe" in (auth.get("operations") or ()), pmtu_protocols=tuple(p for p in ctx.pmtu_protocols if p in PMTU_PROTOCOLS),
        pmtu_families=tuple(f for f in ctx.pmtu_families if f in L3_HEADER), pmtu_max_per_size=max(1, min(int(ctx.pmtu_max_per_size), 5)),
        pmtu_max_sizes=max(1, min(int(ctx.pmtu_max_sizes), 16)), pmtu_max_payload=max(1, min(int(ctx.pmtu_max_payload), 9000)),
        pmtu_max_packet_bytes=max(1, min(int(ctx.pmtu_max_packet_bytes), 200_000)), pmtu_max_pps=max(1, min(int(ctx.pmtu_max_pps), 10)),
        pmtu_max_seconds=max(1.0, min(float(ctx.pmtu_max_seconds), 120.0)))


def requests_for_device(flow: dict, device: str, wanted: Iterable[str], ctx: ProbeContext | None) -> list[col.ProbeRequest]:
    """Only the flow's source originates probes.  Requests carry the explicit flow tuple; a flow that is not a complete TCP tuple yields no TCP request (and
    nothing is invented).  Out-of-scope values are NOT filtered here: the collector refuses them visibly."""
    wanted = set(wanted)
    flow = dict(flow or {})
    if not wanted & set(PROBE_KEYS) or flow.get("src") != device:
        return []
    dst = flow.get("dst")
    if not isinstance(dst, str) or not dst:
        return []
    ctx_ = ctx or ProbeContext()
    dst_addr = _address(dst, ctx) or ""
    src_addr = _address(device, ctx) or ""
    out: list[col.ProbeRequest] = []
    R = col.ProbeRequest
    port = flow.get("port")
    proto = str(flow.get("protocol") or "")
    if "service.probe" in wanted and proto == "tcp":
        out.append(R("tcp_connect", src=device, src_address=src_addr, dst=dst, dst_address=dst_addr, protocol="tcp", port=port if isinstance(port, int) else 0,
                     count=int(ctx_.count)))
    if "path.pmtu" in wanted and ctx is not None and ctx.pmtu_protocols:
        out.append(pmtu_request(flow, device, src_addr, dst, dst_addr, ctx_))
    if "path.trace" in wanted:
        method = ctx_.trace_method
        out.append(R("path_trace", src=device, src_address=src_addr, dst=dst, dst_address=dst_addr, protocol=proto or method, port=port if isinstance(port, int) else 0,
                     method=method, max_hops=int(ctx_.max_hops)))
    return out


def family_of(address: str) -> str:
    ip = _ip(address)
    return "" if ip is None else ("ipv6" if ":" in ip else "ipv4")


def overhead(family: str, protocol: str) -> int:
    return L3_HEADER[family] + L4_HEADER[protocol]


def pmtu_request(flow: dict, device: str, src_addr: str, dst: str, dst_addr: str, ctx: ProbeContext) -> col.ProbeRequest:
    """One bounded DF ladder.  The ladder is derived from the stated service payload (never open-ended); out-of-scope values are refused by the collector."""
    req = ctx.pmtu_required_payload or flow.get("payload_bytes") or flow.get("app_bytes") or 1472
    req = req if isinstance(req, int) and not isinstance(req, bool) and req > 0 else 1472
    if ctx.pmtu_sizes:
        sizes = tuple(ctx.pmtu_sizes)
    else:
        sizes = tuple(sorted({v for v in (548, 1000, 1200, 1400, req) if v <= req}))
    fam = family_of(dst_addr)
    return col.ProbeRequest("pmtu_probe", src=device, src_address=src_addr, dst=dst, dst_address=dst_addr, protocol=ctx.pmtu_protocol, port=ctx.pmtu_udp_port if ctx.pmtu_protocol == "udp" else 0,
                            count=int(ctx.pmtu_per_size), sizes=sizes, family=fam, df=True, required_payload=req, rate_pps=int(ctx.pmtu_rate_pps), max_seconds=float(ctx.pmtu_max_seconds))


def served_keys(requests: Iterable[col.ProbeRequest]) -> set[str]:
    return {r.engine_key() for r in requests}


# ------------------------------------------------------------------------------------------------------------------ response parsing
class ProbeBad(ValueError):
    pass


def _owners(ctx: ProbeContext | None) -> dict:
    out = {}
    if ctx:
        for name, addr in (ctx.addresses or {}).items():
            if _ip(addr):
                out[_ip(addr)] = name
        for addr, name in (ctx.hop_owners or {}).items():
            if _ip(addr):
                out[_ip(addr)] = name
    return out


def _time(value, what: str) -> datetime:
    try:
        return nz.to_utc(value)
    except Exception:  # noqa: BLE001
        raise ProbeBad(f"{what} is not an ISO timestamp") from None


def _rtt(value, timeout_s: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 or value > timeout_s * 1000 * 1.5:
        raise ProbeBad(f"rtt_ms {str(value)[:20]!r} is not a finite non-negative number within the timeout")
    return round(float(value), 3)


def _header(doc, req: col.ProbeRequest, timeout_s: float) -> tuple[dict, datetime, datetime]:
    if not isinstance(doc, dict) or doc.get("schema") != RESPONSE_SCHEMA:
        raise ProbeBad(f"response is not a {RESPONSE_SCHEMA} document")
    if doc.get("op") != req.op:
        raise ProbeBad("response op does not match the request")
    if doc.get("status") != "response":
        raise ProbeBad(f"runner status {str(doc.get('status'))[:20]!r}: no measurement")
    vantage = doc.get("vantage")
    if not isinstance(vantage, dict) or not isinstance(vantage.get("device"), str):
        raise ProbeBad("response carries no vantage device")
    if vantage["device"] != req.src:
        raise ProbeBad(f"VANTAGE_MISMATCH: probe ran from {vantage['device'][:40]!r}, not from the requested source")
    dest = doc.get("destination")
    if not isinstance(dest, dict) or _ip(dest.get("address")) != req.dst_address:
        raise ProbeBad("response destination address does not match the request")
    started, finished = _time(doc.get("started_at"), "started_at"), _time(doc.get("finished_at"), "finished_at")
    if finished < started:
        raise ProbeBad("finished_at precedes started_at")
    return {"device": vantage["device"], "address": _ip(vantage.get("address")) or None, "kind": str(vantage.get("kind") or "")[:40] or None,
            "requested_source": req.src}, started, finished


def _tcp(doc, req: col.ProbeRequest, timeout_s: float) -> dict:
    vantage, started, finished = _header(doc, req, timeout_s)
    if doc.get("protocol") != "tcp" or doc["destination"].get("port") != req.port:
        raise ProbeBad("response protocol/port does not match the requested flow tuple")
    rows = doc.get("attempts")
    if not isinstance(rows, list) or not 1 <= len(rows) <= req.count:
        raise ProbeBad(f"attempts must be a list of 1..{req.count} rows")
    counts = {k: 0 for k in OUTCOMES}
    rtts: list[float] = []
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("outcome") not in OUTCOMES or row.get("seq") != i:
            raise ProbeBad(f"attempt {i} is malformed")
        counts[row["outcome"]] += 1
        if row["outcome"] == "connected":
            rtts.append(_rtt(row.get("rtt_ms"), timeout_s))
        elif row.get("rtt_ms") is not None and row["outcome"] != "refused":
            raise ProbeBad(f"attempt {i} carries an rtt without a completed handshake")
    sent = len(rows) - counts["error"]
    if sent <= 0:
        raise ProbeBad("every attempt was a local runner error: no network verdict")
    flags = []
    quality = nz.Quality.OK
    if counts["error"]:
        flags.append("LOCAL_ERRORS_EXCLUDED")
        quality = nz.Quality.PARTIAL
    if len(rows) < req.count:
        flags.append("SHORT_SAMPLE")
        quality = nz.Quality.PARTIAL
    value = {"layer": "TCP_CONNECT", "protocol": "tcp", "port": req.port, "destination": req.dst_address, "destination_name": req.dst, "requested": req.count,
             "sent": sent, "ok": counts["connected"], "refused": counts["refused"], "timeouts": counts["timeout"], "unreachable": counts["unreachable"],
             "local_errors": counts["error"], "outcomes": [r["outcome"] for r in rows],
             "rtt_ms_p50": round(statistics.median(rtts), 3) if rtts else None, "rtt_ms_min": min(rtts) if rtts else None, "rtt_ms_max": max(rtts) if rtts else None,
             "vantage": vantage, "started_at": nz.iso(started), "finished_at": nz.iso(finished), "l7_verified": False, "production_flow_equivalent": False,
             "limitations": list(TCP_LIMITATIONS)}
    return {"key": "service.probe", "subject": "tcp", "value": value, "quality": quality, "flags": flags, "observed_at": finished}


def _trace(doc, req: col.ProbeRequest, timeout_s: float, ctx: ProbeContext | None) -> dict:
    vantage, started, finished = _header(doc, req, timeout_s)
    if doc.get("method") != req.method:
        raise ProbeBad(f"trace method {str(doc.get('method'))[:12]!r} differs from the requested {req.method!r}")
    rows = doc.get("hops")
    if not isinstance(rows, list) or not 1 <= len(rows) <= req.max_hops:
        raise ProbeBad(f"hops must be a list of 1..{req.max_hops} rows")
    owners = _owners(ctx)
    hops, flags, quality = [], [], nz.Quality.OK
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("ttl") != i or row.get("status") not in HOP_STATUSES:
            raise ProbeBad(f"hop {i} is malformed")
        addr = _ip(row["address"]) if row.get("address") is not None else None
        if row.get("address") is not None and addr is None:
            raise ProbeBad(f"hop {i} address is not an IP")
        if addr is None and row["status"] not in ("timeout", "filtered"):
            raise ProbeBad(f"hop {i} has no address but status {row['status']}")
        hops.append({"ttl": i, "address": addr, "device": owners.get(addr) if addr else None, "status": row["status"],
                     "rtt_ms": _rtt(row["rtt_ms"], timeout_s) if row.get("rtt_ms") is not None else None})
    last = hops[-1]
    reached = last["status"] == "reached" and last["address"] == req.dst_address
    if bool(doc.get("reached")) != reached:
        raise ProbeBad("reached flag is inconsistent with the final hop")
    responding = [h for h in hops if h["address"]]
    first_silent = next((h["ttl"] for h in hops if not h["address"]), None)
    if first_silent is not None and any(h["ttl"] > first_silent for h in responding):
        flags.append("TRACE_GAP_BEFORE_RESPONDING_HOP")
        quality = nz.Quality.UNTRUSTED_PARSE      # positional comparison with the intended path would be wrong
    if any(h["device"] is None for h in responding):
        flags.append("UNRESOLVED_HOP_ADDRESS")
        quality = nz.Quality.UNTRUSTED_PARSE      # an address that maps to no known device cannot be compared with the intended path
    hop_devices = [h["device"] or h["address"] for h in responding]
    value = {"method": req.method, "reached": reached, "hop_devices": hop_devices, "last_hop": hop_devices[-1] if hop_devices else "", "hops": hops,
             "max_hops": req.max_hops, "destination": req.dst_address, "destination_name": req.dst, "vantage": vantage, "started_at": nz.iso(started),
             "finished_at": nz.iso(finished), "production_flow_equivalent": req.method == "tcp" and False,
             "limitations": list(TRACE_LIMITATIONS) + ([] if req.method == "tcp" else [f"{req.method} trace: not proof of the path taken by the TCP production flow"])}
    return {"key": "path.trace", "subject": req.dst, "value": value, "quality": quality, "flags": flags, "observed_at": finished}


def _pmtu(doc, req: col.ProbeRequest, timeout_s: float) -> dict:
    vantage, started, finished = _header(doc, req, timeout_s)
    if doc.get("protocol") != req.protocol or doc.get("family") != req.family:
        raise ProbeBad("response protocol/address family does not match the request")
    if doc.get("df") is not True:
        raise ProbeBad("DF was not set on the probes: PMTUD behaviour was not exercised")
    if (finished - started).total_seconds() > req.max_seconds + timeout_s:
        raise ProbeBad("probe run exceeded the authorized time budget")
    vis = doc.get("ptb_visibility", "unknown")
    if vis not in PTB_VISIBILITY:
        raise ProbeBad("ptb_visibility is not one of observable/not_observable/unknown")
    rows = doc.get("trials")
    if not isinstance(rows, list) or not 1 <= len(rows) <= len(req.sizes) * req.count:
        raise ProbeBad(f"trials must be a list of 1..{len(req.sizes) * req.count} rows")
    hdr = overhead(req.family, req.protocol)
    per: dict[int, dict] = {s_: {"sent": 0, "reply": 0, "ptb": 0, "timeout": 0, "error": 0, "ptb_mtu": []} for s_ in req.sizes}
    wire_bytes = 0
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("outcome") not in PMTU_OUTCOMES:
            raise ProbeBad(f"trial {i} is malformed")
        pay = row.get("payload_bytes")
        if isinstance(pay, bool) or pay not in per:
            raise ProbeBad(f"trial {i} payload size was not requested")
        if row.get("packet_bytes") != pay + hdr:
            raise ProbeBad(f"trial {i} packet_bytes is not payload + {hdr} header bytes (payload and packet size confused)")
        a = per[pay]
        if a["sent"] >= req.count:
            raise ProbeBad(f"more than {req.count} trials for payload {pay}")
        if row["outcome"] == "ptb":
            mtu = row.get("ptb_mtu")
            if isinstance(mtu, bool) or not isinstance(mtu, int) or not (1280 if req.family == "ipv6" else 68) <= mtu < pay + hdr:
                raise ProbeBad(f"trial {i} PTB carries no plausible next-hop MTU below the probe packet size")
            a["ptb_mtu"].append(mtu)
        elif row.get("ptb_mtu") is not None:
            raise ProbeBad(f"trial {i} carries a PTB MTU without a PTB")
        if row["outcome"] == "reply":
            _rtt(row.get("rtt_ms"), timeout_s)
        a["sent"] += 1
        a["error" if row["outcome"] in ("error", "local_too_big") else row["outcome"]] += 1
        wire_bytes += pay + hdr
    if wire_bytes > req.max_packet_bytes():
        raise ProbeBad("probe wire bytes exceed the authorized byte budget")
    table, flags, quality = [], [], nz.Quality.OK
    for pay in sorted(per):
        a = per[pay]
        net = a["sent"] - a["error"]
        status = "unknown" if net <= 0 else "pass" if a["reply"] == net else "fail" if a["reply"] == 0 else "partial"
        table.append({"data_bytes": pay, "packet_bytes": pay + hdr, "sent": a["sent"], "reply": a["reply"], "ptb": a["ptb"], "timeout": a["timeout"], "local_errors": a["error"],
                      "status": status, "ptb_mtu": min(a["ptb_mtu"]) if a["ptb_mtu"] else None})
    passed = [t["data_bytes"] for t in table if t["status"] == "pass"]
    failed = [t["data_bytes"] for t in table if t["status"] == "fail"]
    tested = [t["data_bytes"] for t in table if t["status"] != "unknown"]
    max_ok = max(passed) if passed else None
    monotonic = not (failed and passed and max_ok > min(failed)) and not any(t["status"] == "partial" for t in table)
    ptb_mtus = [t["ptb_mtu"] for t in table if t["ptb_mtu"]]
    ptb = any(t["ptb"] for t in table)
    complete = len(tested) == len(req.sizes) and all(t["sent"] == req.count for t in table)
    if not complete:
        flags.append("PMTU_COVERAGE_INCOMPLETE")
        quality = nz.Quality.PARTIAL
    if not monotonic:
        flags.append("PMTU_NON_MONOTONIC")
        quality = nz.Quality.PARTIAL
    value = {"schema": PMTU_SCHEMA, "layer": "PMTU_DF_PROBE", "protocol": req.protocol, "family": req.family, "df": True, "destination": req.dst_address, "destination_name": req.dst,
             "header_overhead": hdr, "size_semantics": "L4 payload bytes (packet size = payload + header_overhead)", "sizes": table, "tested_sizes": tested,
             "largest_tested_size": max(tested) if tested else None, "max_ok": max_ok, "max_ok_size": max_ok, "max_ok_packet": max_ok + hdr if max_ok is not None else None,
             "min_fail_size": min(failed) if failed else None, "required_size": req.required_payload, "complete": complete, "monotonic": monotonic,
             "ptb_received": ptb, "ptb_mtu": min(ptb_mtus) if ptb_mtus else None, "ptb_visibility": "observed" if ptb else vis, "rate_pps": req.rate_pps,
             "packets_sent": sum(t["sent"] for t in table), "wire_bytes": wire_bytes, "vantage": vantage, "started_at": nz.iso(started), "finished_at": nz.iso(finished),
             "tcp_behavior_verified": False, "production_flow_equivalent": False, "limitations": list(PMTU_LIMITATIONS)}
    return {"key": "path.pmtu", "subject": req.dst, "value": value, "quality": quality, "flags": flags, "observed_at": finished}


def parse_response(raw: str, req: col.ProbeRequest, *, timeout_s: float, ctx: ProbeContext | None = None) -> dict:
    """One runner document -> ``{key, subject, value, quality, flags, observed_at}``; raises :class:`ProbeBad` (the caller records PARSE_FAILED, never a value)."""
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        raise ProbeBad("response is not valid JSON") from None
    if req.op == "tcp_connect":
        return _tcp(doc, req, timeout_s)
    return _pmtu(doc, req, timeout_s) if req.op == "pmtu_probe" else _trace(doc, req, timeout_s, ctx)
