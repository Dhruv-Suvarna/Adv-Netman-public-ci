"""DNS source adapter: derives the typed, bounded request set RB05 needs from the case's DNS target and wires an injected read-only runner into the runtime.

Flow: ``runtime.CollectorProvider`` -> ``requests_for_device`` (this module; validates names/servers, never invents a target) -> ``collectors.DnsCollector`` (budgeted,
admission-checked, calls the injected runner) -> ``normalization.normalize_dns`` (parser ``dns.response`` / ``dns-json-1.0``) -> ``runtime.map_observations`` -> engine keys
``dns.resolver_config``, ``dns.transport``, ``dns.query``, ``dns.soa``, ``dns.xfr``, ``dns.delegation``, ``dns.records``, ``dns.dnssec``, ``time.sync`` consumed by RB05 DN01..DN10.

Nothing here opens a socket.  The runner (``DnsRunner``: ``execute(request_dict) -> JSON text``) is supplied by the caller (e.g. a gateway-attested read-only
adapter); without it every DNS key is an explicit missing-data record (``NOT_CONFIGURED``) and RB05 reports INCONCLUSIVE/UNAVAILABLE -- never PASS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Protocol

from .. import collectors as col
from .. import normalization as nz

SOURCE_VERSION = "1.0.0"
PARSER_ID = "dns.response"
LIVE, RECORDED, SIMULATED = "LIVE_GATEWAY_PINNED", "RECORDED", "SIMULATED"
DNS_KEYS = ("dns.resolver_config", "dns.transport", "dns.query", "dns.soa", "dns.xfr", "dns.delegation", "dns.records", "dns.dnssec", "time.sync")


class DnsRunner(Protocol):
    """Injected, authorized, read-only.  Receives ``{schema: nmas.dns.request/1, op, server, name, zone, qtype, role, transport, timeout_s, read_only: true}`` and returns one
    ``nmas.dns.response/1`` JSON document.  May raise ``TimeoutError`` / ``collectors.TransportError`` / ``collectors.PermissionDenied``.  Optional ``provenance()``."""

    def execute(self, request: dict): ...


@dataclass
class DnsContext:
    """``RuntimeDeps.dns_context``.  ``vantage_servers`` lets split-horizon checks name the resolvers a non-client vantage device is asked about
    ({device: [resolver, ...]}); absent => those queries are not made and DN08 stays INCONCLUSIVE.  ``extra_servers`` widens the authorized-target set."""

    vantage_servers: dict = field(default_factory=dict)
    extra_servers: tuple = ()
    aaaa_expected: bool | None = None


def describe_source(*, gateway: dict | None = None, recorded: bool = False) -> dict:
    """Provenance label.  Only a gateway-recorded run (``gateway['live']`` is True) is LIVE; anything else is never presented as live."""
    label = LIVE if gateway and gateway.get("live") is True else (RECORDED if recorded else SIMULATED)
    return {"source": "dns", "label": label, "live": label == LIVE, "parser": {"id": PARSER_ID, "version": nz.PARSERS[PARSER_ID][0].version},
            "dnssec": "reported only when the runner supplies AD/RRSIG/DS evidence; otherwise a missing-data record", "gateway": gateway or None, "adapter_version": SOURCE_VERSION}


def _servers(target: dict, ctx: DnsContext | None) -> tuple[list[str], list[str], list[str]]:
    resolvers = [str(x) for x in target.get("resolvers") or []]
    auth = [str(x) for x in target.get("authoritative") or []]
    extra = [str(x) for x in (ctx.extra_servers if ctx else ())]
    for devs in (ctx.vantage_servers.values() if ctx else ()):
        extra += [str(x) for x in devs]
    return resolvers, auth, extra


def allowed_servers(target: dict, ctx: DnsContext | None = None) -> list[str]:
    r, a, e = _servers(target, ctx)
    return r + a + e


def requests_for_device(target: dict, device: str, wanted: Iterable[str], ctx: DnsContext | None = None) -> list[col.DnsRequest]:
    """The ordered request set for ``device`` given the engine's wanted keys.  The case target is ``{client, name, zone, resolvers, authoritative, dnssec?}``.
    Only the client asks resolver/authoritative servers; an authoritative server is only asked for its transfer status; unknown devices get nothing."""
    wanted = set(wanted)
    name, zone = target.get("name", ""), target.get("zone", "")
    resolvers, auth, _ = _servers(target, ctx)
    out: list[col.DnsRequest] = []
    R = col.DnsRequest
    if device == target.get("client"):
        if "dns.resolver_config" in wanted:
            out.append(R("resolver_config"))
        if "dns.transport" in wanted:
            out += [R("transport", server=r) for r in resolvers]
        if "dns.query" in wanted:
            out += [R("query", server=r, name=name, qtype="A", role="recursive") for r in resolvers]
            out += [R("query", server=a, name=name, qtype="A", role="authoritative") for a in auth]
        if "dns.soa" in wanted:
            out += [R("soa", server=a, zone=zone, role="authoritative") for a in auth]
        if wanted & {"dns.delegation", "dns.soa"}:     # DN05 reads the delegation as an optional companion of the SOA check but does not list it in its sources
            out.append(R("delegation", zone=zone))
        if "dns.records" in wanted:
            out.append(R("records", name=name, aaaa_expected=ctx.aaaa_expected if ctx else None))
        if "dns.dnssec" in wanted and target.get("dnssec") and resolvers:
            out.append(R("dnssec", zone=zone, server=resolvers[0]))
        if "time.sync" in wanted:
            out.append(R("time_sync"))
    else:
        if device in auth and "dns.xfr" in wanted:
            out.append(R("zone_status", server=device, zone=zone))
        if "dns.query" in wanted and ctx and device in ctx.vantage_servers:
            out += [R("query", server=r, name=name, qtype="A", role="recursive") for r in ctx.vantage_servers[device]]
    return out


def served_keys(requests: Iterable[col.DnsRequest]) -> set[str]:
    return {nz.dns_engine_key(r.as_dict())[0] for r in requests}


def ttl_recovery(observation_value: dict, observed_at: datetime, now: datetime) -> dict:
    """TTL-aware recovery state of ONE cached answer observation (``dns.query`` value): until ``expires_at`` a stale answer is still legitimately served, so a
    re-check before that time can neither prove recovery nor disprove it.  Returns ``{state: WAITING_TTL|RECHECK_DUE|NO_TTL, recheck_at, remaining_s}``."""
    ttl = observation_value.get("ttl")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        return {"state": "NO_TTL", "recheck_at": None, "remaining_s": 0}
    due = observed_at + timedelta(seconds=ttl)
    remaining = (due - now).total_seconds()
    return {"state": "WAITING_TTL" if remaining > 0 else "RECHECK_DUE", "recheck_at": nz.iso(due), "remaining_s": max(0, int(remaining))}
