"""RB05 -- DNS resolution and zone-propagation failures.  Differentiates authoritative failure, cache/TTL and DNS policy (UT-050)."""

from __future__ import annotations

from .base import CONTEXT, Ctx, Finding, Hypothesis, Result, Runbook, TestSpec, fault, inconclusive, ok


def _t(ctx):
    return ctx.case["target"]


def dn01(ctx: Ctx) -> Result:
    t = _t(ctx)
    o = ctx.need("dns.resolver_config", t["client"], "resolv")
    want = ctx.intent.get("services", {}).get("resolvers", t["resolvers"])
    ctx.use_intent("intent")
    probs = []
    if list(o.value["nameservers"]) != list(want):
        probs.append(f"client nameservers {o.value['nameservers']} != intended {want}")
    if t["name"].count(".") == 0 and not o.value.get("search"):
        probs.append("single-label name but no search domain configured")
    if probs:
        return fault("; ".join(probs), Finding("F-client-dns", "Client resolver configuration differs from intent", "dns", t["client"], "H-client", True, 0.8), **o.value)
    return ok(f"resolv.conf: nameservers {o.value['nameservers']}, search {o.value.get('search')}", "client resolver configuration as intended", **o.value)


def dn02(ctx: Ctx) -> Result:
    t = _t(ctx)
    bad = []
    for r in t["resolvers"]:
        o = ctx.need("dns.transport", t["client"], r)
        if not o.value.get("udp_ok") or not o.value.get("tcp_ok") or o.value.get("acl_refused"):
            bad.append(f"{r}: udp53={o.value.get('udp_ok')} tcp53={o.value.get('tcp_ok')} {o.value.get('detail', '')}")
    if bad:
        return fault("; ".join(bad), Finding("F-dns-transport", "UDP/TCP 53 not reachable", "dns", t["client"], "H-policy", True, 0.8), problems=bad)
    return ok("UDP and TCP 53 reachable to every resolver", "transport fine", resolvers=t["resolvers"])


SERIAL_MOD = 2 ** 32
SERIAL_HALF = 2 ** 31
SUCCESS_NEGATIVE = ("NXDOMAIN", "NODATA")


def serial_valid(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x < SERIAL_MOD


def serial_compare(a: int, b: int):
    """RFC 1982 serial-number arithmetic (SERIAL_BITS=32): -1 if a<b, 0 if equal, 1 if a>b, None when the order is undefined (distance exactly 2**31)."""
    if not (serial_valid(a) and serial_valid(b)):
        raise ValueError("serial is not an unsigned 32-bit integer")
    if a == b:
        return 0
    if (b - a) % SERIAL_MOD == SERIAL_HALF:
        return None
    return -1 if (b - a) % SERIAL_MOD < SERIAL_HALF else 1


def analyse_serials(serials: dict) -> dict:
    """Order SOA serials by RFC 1982.  ``state``: EQUAL | ORDERED (``newest`` + ``lagging``) | AMBIGUOUS (undefined pair or no single newest value) | INVALID.
    A numeric max() is never used: after wraparound the numerically smaller serial can be the newer one."""
    bad = [ns for ns, v in serials.items() if not serial_valid(v)]
    if bad:
        return {"state": "INVALID", "reason": f"serial from {bad} is not an unsigned 32-bit integer"}
    vals = sorted(set(serials.values()))
    if len(vals) <= 1:
        return {"state": "EQUAL", "newest": vals[0] if vals else None, "lagging": {}}
    for i, x in enumerate(vals):
        for y in vals[i + 1:]:
            if serial_compare(x, y) is None:
                return {"state": "AMBIGUOUS", "reason": f"serials {x} and {y} are exactly 2^31 apart: RFC 1982 order is undefined"}
    newest = [x for x in vals if all(serial_compare(x, y) >= 0 for y in vals)]
    if len(newest) != 1:
        return {"state": "AMBIGUOUS", "reason": f"no single newest serial among {vals} under RFC 1982 (cyclic ordering)"}
    return {"state": "ORDERED", "newest": newest[0], "lagging": {ns: v for ns, v in serials.items() if v != newest[0]}}


def _intended(ctx: Ctx, name: str):
    """(known, list_of_addresses).  An intended-ABSENT name is declared by ``services.dns_absent`` (list) or an explicit empty/None entry in ``dns_names``."""
    svc = ctx.intent.get("services", {}) or {}
    ctx.use_intent("intent")
    if name in (svc.get("dns_absent") or []):
        return True, []
    names = svc.get("dns_names", {}) or {}
    if name not in names:
        return False, []
    v = names[name]
    if v is None:
        return True, []
    return True, sorted(v) if isinstance(v, (list, tuple)) else [v]


def _classify(v: dict) -> str:
    rc = str(v.get("rcode", "")).upper()
    if rc == "NOERROR":
        return "ANSWER" if v.get("answers") else "NODATA"
    return rc or "UNKNOWN"


def dn03(ctx: Ctx) -> Result:
    t = _t(ctx)
    ans = {}
    for r in t["resolvers"]:
        o = ctx.need("dns.query", t["client"], f"{t['name']}/{r}")
        v = o.value
        ans[r] = {"rcode": v["rcode"], "kind": _classify(v), "answers": sorted(v.get("answers", [])), "ttl": v.get("ttl"), "negative": bool(v.get("negative")), "cache": v.get("cache")}
    known, want = _intended(ctx, t["name"])
    if not known:
        return inconclusive(f"no intended answer for {t['name']} in NetBox/DNS intent; recursive answers cannot be judged", per_resolver=ans)
    absent = not want
    policy = [r for r, a in ans.items() if a["kind"] in ("REFUSED", "SERVFAIL")]
    other = [r for r, a in ans.items() if a["kind"] not in ("ANSWER", "NODATA", "NXDOMAIN", "REFUSED", "SERVFAIL")]
    negative = [r for r, a in ans.items() if a["kind"] in SUCCESS_NEGATIVE]
    wrong = [r for r, a in ans.items() if a["kind"] == "ANSWER" and a["answers"] != want]
    if policy:
        return fault(f"{policy} answer REFUSED/SERVFAIL for {t['name']}", Finding("F-resolver-refused", "Resolver refuses or fails the query (policy or backend failure)", "dns", policy[0], "H-policy", False, 0.6, "see DN02/DN04 to separate DNS ACL from authoritative failure"), per_resolver=ans)
    if other:
        return fault(f"{other} return non-success rcode {[ans[r]['rcode'] for r in other]} for {t['name']}", Finding("F-resolver-nonsuccess", "Resolver returns an unexpected non-success response", "dns", other[0], "H-policy", False, 0.4, "compare with authoritative answers (DN04) before concluding"), per_resolver=ans)
    if absent:
        resolving = [r for r, a in ans.items() if a["kind"] == "ANSWER"]
        if resolving:
            return fault(f"{t['name']} is intended to be absent but {resolving} return {[ans[r]['answers'] for r in resolving]}", Finding("F-resolver-unexpected-answer", "Intended-absent name resolves", "dns", resolving[0], "H-cache", False, 0.5, "DN04/DN06 separate a cached positive answer from authoritative data"), per_resolver=ans)
        return ok(f"{t['name']} is intended absent and every resolver reports {sorted({a['kind'] for a in ans.values()})}", "intended absence confirmed (recursive view; the rcode alone does not prove which side is authoritative)", per_resolver=ans)
    if negative:
        cached = [r for r in negative if ans[r]["negative"] or ans[r]["cache"] == "hit" or (ans[r]["ttl"] or 0) > 0]
        return fault(f"unexpected {[ans[r]['kind'] for r in negative]} from {negative} for {t['name']} (intended {want}); " + (f"possible negative cache on {cached}" if cached else "cache state unknown"),
                     Finding("F-resolver-negative", "Resolver returns NXDOMAIN/NODATA for a name that should resolve", "dns", negative[0], "H-cache", False, 0.5,
                             "DN04 (authoritative) and DN06 (negative TTL) decide between stale negative cache and authoritative absence"), "negative response is a symptom; cause is not yet attributed", per_resolver=ans)
    if wrong:
        return fault(f"{wrong} return {[ans[r]['answers'] for r in wrong]} (intended {want})", Finding("F-resolver-stale", "Recursive answer differs from intent", "dns", wrong[0], "H-cache", False, 0.6), per_resolver=ans)
    return ok(f"all resolvers answer {want}", "recursive answers consistent with intent", per_resolver=ans)


def dn04(ctx: Ctx) -> Result:
    t = _t(ctx)
    ans = {}
    for ns in t["authoritative"]:
        o = ctx.need("dns.query", t["client"], f"{t['name']}/{ns}")
        ans[ns] = {"rcode": o.value["rcode"], "answers": sorted(o.value.get("answers", [])), "aa": o.value.get("aa"), "ttl": o.value.get("ttl")}
    sets = {tuple(a["answers"]) for a in ans.values()}
    dead = [ns for ns, a in ans.items() if a["rcode"] != "NOERROR" or not a.get("aa")]
    if dead or len(sets) > 1:
        return fault(f"authoritative servers disagree/fail: {ans}", Finding("F-auth-inconsistent", "Authoritative servers do not serve the same data", "dns", dead[0] if dead else t["authoritative"][0], "H-auth", True, 0.85,
                     "repair replication on the stale server; coordinate with the zone owner"), "authoritative inconsistency is the root, resolver behaviour is downstream", per_ns=ans)
    return ok(f"all authoritative servers answer {list(sets)[0]} (AA set)", "authoritative data consistent", per_ns=ans)


def dn05(ctx: Ctx) -> Result:
    t = _t(ctx)
    ser, x, untrusted = {}, {}, []
    for ns in t["authoritative"]:
        s = ctx.need("dns.soa", t["client"], f"{t['zone']}/{ns}")
        if s.value.get("aa") is False:
            untrusted.append(ns)       # non-authoritative SOA is a cached copy, not the server's own serial
            continue
        ser[ns] = s.value["serial"]
        xf = ctx.opt("dns.xfr", ns, t["zone"])
        if xf is not None:
            x[ns] = xf.value
    deleg = ctx.opt("dns.delegation", t["client"], t["zone"])
    unc = []
    if untrusted:
        unc.append(f"SOA from {untrusted} lacks the AA flag: not authoritative serial evidence")
    an = analyse_serials(ser) if ser else {"state": "INVALID", "reason": "no authoritative serial collected"}
    lag = an.get("lagging", {})
    if an["state"] in ("AMBIGUOUS", "INVALID"):
        unc.append(an["reason"])
    xfr_unknown = [ns for ns in t["authoritative"] if ns not in x and ns in ser]
    probs, finding_causal = [], False
    if lag:
        failed = {ns: x[ns].get("last_result") for ns in lag if ns in x}
        bad_xfr = {ns: r for ns, r in failed.items() if str(r or "").strip().lower() not in ("ok", "success", "succeeded")}
        finding_causal = bool(bad_xfr)
        probs.append(f"SOA serial behind (RFC 1982) on {lag} (newest {an['newest']}); transfer status {failed or 'unknown'}"
                     + ("" if bad_xfr else "; no failed transfer evidence, cause not attributed"))
    lame = (deleg.value.get("lame") or []) if deleg is not None else []
    if lame:
        probs.append(f"lame delegation: {lame}")
    if deleg is not None and "ns" in deleg.value and not deleg.value["ns"]:
        probs.append("missing delegation: no NS records for the zone")
    if deleg is None:
        unc.append("delegation evidence (dns.delegation) not collected: delegation health unknown")
    elif deleg.value.get("unknown"):
        unc.append(f"delegated servers {deleg.value['unknown']} did not answer: delegation health unknown for them")
    if xfr_unknown and (lag or an["state"] == "EQUAL"):
        unc.append(f"zone-transfer status unknown for {xfr_unknown}")
    if probs:
        extra = ("; unresolved: " + "; ".join(unc)) if unc else ""
        if lag:
            fnd = Finding("F-zone-propagation", "Zone not propagated to every authoritative server" + (" (transfer/replication failure)" if finding_causal else " (cause unproven)"), "dns", next(iter(lag)), "H-auth", finding_causal, 0.9 if finding_causal else 0.5,
                          "fix the transfer ACL/TSIG/notify path on the stale secondary, then re-check serials; no record edits" if finding_causal else "collect zone transfer status from the lagging server before attributing a cause")
            why = "serial skew with a failed transfer proves the propagation fault" if finding_causal else "serial skew is real but no transfer evidence attributes it (refresh interval vs failure unknown)"
        else:
            fnd = Finding("F-lame-delegation", "Delegation is missing or lame", "dns", (lame or [t["authoritative"][0]])[0] if lame else t["authoritative"][0], "H-auth", True, 0.8,
                          "correct the parent NS/glue or the child server's authority; zone owner approval")
            why = "delegation evidence shows the fault"
        return fault("; ".join(probs) + extra, fnd, why, serials=ser, xfr=x, serial_state=an["state"], uncertainty=unc)
    if unc:
        return inconclusive("; ".join(unc), "DN05 cannot call the zone healthy: " + "; ".join(unc), serials=ser, xfr=x, serial_state=an["state"], uncertainty=unc)
    return ok(f"SOA serial {an['newest']} identical on all {len(ser)} authoritative servers; delegation and transfers healthy", "zone propagated", serials=ser, xfr=x)


def dn06(ctx: Ctx) -> Result:
    t = _t(ctx)
    auth = ctx.need("dns.query", t["client"], f"{t['name']}/{t['authoritative'][0]}")
    if auth.value.get("rcode") != "NOERROR" or auth.value.get("aa") is not True:
        return inconclusive(f"authoritative reference from {t['authoritative'][0]} is not an AA NOERROR answer (rcode {auth.value.get('rcode')}, aa {auth.value.get('aa')}); cache comparison has no trusted baseline",
                            reference=auth.value)
    auth_ans = sorted(auth.value.get("answers", []))
    stale = []
    for r in t["resolvers"]:
        o = ctx.need("dns.query", t["client"], f"{t['name']}/{r}")
        v = o.value
        ttl = v.get("ttl") or 0
        kind = _classify(v)
        if kind == "ANSWER" and sorted(v["answers"]) != auth_ans and ttl > 0 and auth_ans:
            stale.append({"resolver": r, "cached": v["answers"], "authoritative": auth.value["answers"], "ttl_remaining_s": ttl, "negative": False})
        elif kind in SUCCESS_NEGATIVE and auth_ans and ttl > 0:
            stale.append({"resolver": r, "cached": [], "cached_rcode": kind, "authoritative": auth.value["answers"], "ttl_remaining_s": ttl, "negative": True})
    if stale:
        eta = max(s["ttl_remaining_s"] for s in stale)
        neg = any(s["negative"] for s in stale)
        return fault(f"resolver cache holds a superseded {'negative ' if neg else ''}answer: {stale}", Finding("F-cache-ttl", "Stale " + ("negative " if neg else "") + "cache entry (self-heals after TTL)", "dns", stale[0]["resolver"], "H-cache", True, 0.85,
                     f"wait for TTL expiry (<= {eta}s) or, with approval, flush that one name on that one resolver"), "authoritative (AA) is correct; only the cache lags: do not edit the zone", stale=stale, recovery_eta_s=eta)
    return ok("no resolver serves a cached answer that differs from the authoritative one", "cache/TTL not implicated")


def dn07(ctx: Ctx) -> Result:
    t = _t(ctx)
    o = ctx.need("dns.records", t["client"], t["name"])
    v = o.value
    probs = []
    if v.get("cname_loop") or (v.get("cname") and v.get("a")):
        probs.append("CNAME coexists with other data or loops")
    if v.get("a") and v.get("ptr") and v["ptr"] != t["name"]:
        probs.append(f"PTR {v['ptr']} != forward name")
    if v.get("aaaa_expected") and not v.get("aaaa"):
        probs.append("AAAA expected but missing")
    if probs:
        return fault("; ".join(probs), Finding("F-record", "A/AAAA/CNAME/PTR inconsistency", "dns", t["client"], "H-auth", True, 0.7), **v)
    return ok("A/AAAA/CNAME/PTR consistent", "records coherent", **v)


def dn08_applies(ctx: Ctx):
    return (bool(ctx.intent.get("services", {}).get("split_horizon")), "no split-horizon views in the NetBox/DNS intent for this zone")


def dn08(ctx: Ctx) -> Result:
    t = _t(ctx)
    views = ctx.intent["services"]["split_horizon"]
    bad = []
    for view_name, spec in views.items():
        o = ctx.need("dns.query", spec["vantage"], f"{t['name']}/{spec['resolver']}")
        if sorted(o.value["answers"]) != sorted(spec["expected"]):
            bad.append(f"view {view_name}: {o.value['answers']} != expected {spec['expected']}")
    if bad:
        return fault("; ".join(bad), Finding("F-split-horizon", "Split-horizon view returns the wrong answer", "dns", hypothesis="H-auth", causal=True, confidence=0.8), problems=bad)
    return ok(f"{len(views)} views return their intended answers", "views consistent")


def dn09_applies(ctx: Ctx):
    return (bool(_t(ctx).get("dnssec")), "zone is not signed (DNSSEC not in scope for this name)")


def dn09(ctx: Ctx) -> Result:
    t = _t(ctx)
    o = ctx.need("dns.dnssec", t["client"], t["zone"])
    v = o.value
    if not v.get("ad") or v.get("rrsig_days_left", 99) < 1 or not v.get("ds_match", True):
        return fault(f"validation failing: ad={v.get('ad')} rrsig days left {v.get('rrsig_days_left')} ds_match={v.get('ds_match')}", Finding("F-dnssec", "DNSSEC validation failure", "dns", t["client"], "H-auth", True, 0.8), **v)
    return ok(f"validated (AD), RRSIG {v.get('rrsig_days_left')} days left, DS matches", "DNSSEC healthy", **v)


def dn10(ctx: Ctx) -> Result:
    t = _t(ctx)
    ts = ctx.opt("time.sync", t["client"], "")
    ch = [r for r in ctx.correlation.get("changes", []) if r["relation"] == "BEFORE_ONSET" and (r.get("kind") in ("dns", "zone") or any(d in t["authoritative"] + t["resolvers"] for d in r.get("devices", [])))]
    ctx.use_intent("changes")
    if ts is not None and abs(ts.value.get("offset_ms", 0)) > 5000:
        return fault(f"client clock offset {ts.value['offset_ms']} ms (affects DNSSEC validity)", Finding("F-time", "Time not synchronised", "dns", t["client"], "H-client", False, 0.6), **ts.value)
    unapproved = [r["change_id"] for r in ch if not r.get("authorized", r.get("approved"))]
    if unapproved:
        return fault(f"unapproved DNS/zone change(s) {unapproved} precede onset", Finding("F-dns-change", "Unapproved DNS change precedes the failure", "change", hypothesis="H-change", confidence=0.4), changes=unapproved)
    return ok(f"time synchronised; {len(ch)} approved DNS change(s) in window (recorded, not blamed)", "no time/change explanation", approved=[r["change_id"] for r in ch])


RB05 = Runbook(
    id="RB05", name="dns-resolution-zone-propagation", version="1.1.0", title="DNS resolution and zone-propagation failures", doc="RB05-dns.md", test_prefixes=("DN",),
    purpose="Separate client configuration, DNS policy/transport, authoritative inconsistency, replication lag, cache/TTL and DNSSEC causes for a name-specific failure.",
    tests=(
        TestSpec("DN01", "Client resolv.conf and search paths", "L7", "H-client", "client resolvers as intended", dn01, command="dns.resolver_config", condition="client misconfiguration", sources=("dns.resolver_config", "intent")),
        TestSpec("DN02", "UDP/TCP 53 reachability and source-specific policy", "L4", "H-policy", "both transports reachable", dn02, command="dns.transport", condition="DNS ACL / forwarding policy", sources=("dns.transport",)),
        TestSpec("DN03", "Recursive answers per resolver", "L7", "H-cache", "all resolvers answer the intended record", dn03, command="dns.query(resolver)", cls=CONTEXT, condition="resolver disagreement", sources=("dns.query",)),
        TestSpec("DN04", "Authoritative answers per NS", "L7", "H-auth", "every NS serves the same data (AA)", dn04, command="dns.query(authoritative)", condition="authoritative inconsistency", sources=("dns.query",)),
        TestSpec("DN05", "SOA serial, NS delegation, zone transfer", "L7", "H-auth", "identical serials, healthy transfers", dn05, command="dns.soa+dns.xfr+dns.delegation", condition="zone not propagated", sources=("dns.soa", "dns.xfr", "dns.delegation")),
        TestSpec("DN06", "Cache and negative TTL vs authoritative", "L7", "H-cache", "no stale cache", dn06, command="dns.query(ttl)", after=("DN04",), condition="stale cache within TTL", sources=("dns.query",)),
        TestSpec("DN07", "A/AAAA/CNAME/PTR consistency", "L7", "H-auth", "records coherent", dn07, command="dns.records", condition="record inconsistency", sources=("dns.records",)),
        TestSpec("DN08", "Split-horizon views", "L7", "H-auth", "each view returns its intended answer", dn08, applies=dn08_applies, command="dns.query(views)", condition="wrong view answer", sources=("dns.query", "intent")),
        TestSpec("DN09", "DNSSEC validation", "L7", "H-auth", "validated, signatures fresh", dn09, applies=dn09_applies, command="dns.dnssec", condition="validation failure", sources=("dns.dnssec",)),
        TestSpec("DN10", "Time synchronisation and recent DNS changes", "CTRL", "H-change", "clock sane, no unapproved DNS change", dn10, command="time.sync+changes", cls=CONTEXT, condition="time skew / change", sources=("time.sync", "changes")),
    ),
    hypotheses=(
        Hypothesis("H-client", "Client resolver configuration or clock", "dns", ("DN01",), 2),
        Hypothesis("H-policy", "DNS ACL / source-specific forwarding policy or transport", "policy", ("DN02",), 2),
        Hypothesis("H-cache", "Stale cache / negative caching within TTL", "dns", ("DN03", "DN06"), 3),
        Hypothesis("H-auth", "Authoritative inconsistency, replication failure, record or view error", "dns", ("DN04", "DN05", "DN07", "DN08", "DN09"), 1),
        Hypothesis("H-change", "A recent DNS/zone change", "change", ("DN10",), 4),
    ),
    orders={"top-down": ("DN10", "DN01", "DN02", "DN03", "DN04", "DN05", "DN06", "DN07", "DN08", "DN09"),
            "divide-and-conquer": ("DN10", "DN03", "DN04", "DN05", "DN06", "DN01", "DN02", "DN07", "DN08", "DN09")},
    select_strategy=lambda ctx: ("divide-and-conquer", "compare recursive vs authoritative answers first to split client/resolver from zone-side causes") if len(ctx.case["target"]["resolvers"]) > 1 or len(ctx.case["target"]["authoritative"]) > 1
    else ("top-down", "single resolver/NS: descend from client configuration"),
    remediations={
        "F-zone-propagation": {"tier": 2, "action": "repair transfer/notify on the stale secondary (ACL/TSIG); verify serial convergence", "approvals": ["DNS owner approval"], "pre_tests": ["DN04", "DN05"], "post_tests": ["DN05", "DN04", "DN03"],
                               "rollback": "restore previous transfer config", "never": ["editing records on the secondary", "serial manipulation"]},
        "F-cache-ttl": {"tier": 2, "action": "wait for TTL expiry; optional single-name cache flush on one resolver with approval", "approvals": ["operator approval for flush"], "pre_tests": ["DN06", "DN04"], "post_tests": ["DN03", "DN06"],
                        "rollback": "n/a (cache repopulates)", "never": ["flush all caches", "zone edits"]},
        "F-dns-transport": {"tier": 2, "action": "narrow ACL correction permitting the client subnet to the resolver on UDP/TCP 53", "approvals": ["operator approval", "dry-run"], "pre_tests": ["DN02"], "post_tests": ["DN02", "DN03"],
                            "rollback": "restore ACL line", "never": ["open DNS to any"]},
        "F-resolver-refused": {"tier": 2, "action": "see DN02: confirm policy before change", "approvals": ["operator approval"], "pre_tests": ["DN02"], "post_tests": ["DN03"], "rollback": "restore policy", "never": []},
    },
)
