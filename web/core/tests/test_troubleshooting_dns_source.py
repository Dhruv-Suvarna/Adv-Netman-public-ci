"""DNS source (RB05) -- parser -> collector -> runtime -> RB05.  Stable IDs DNSSRC-001 .. DNSSRC-020 (supports UT-050 / IT-08).

PROVENANCE: every response document below is SIMULATED (hand-written to the ``nmas.dns.response/1`` schema produced by an injected read-only runner).  No
gateway-recorded DNS output is pinned, so nothing here claims live verification; the injected gateway dict (``live=False``) only proves provenance is carried verbatim.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import dns as dns_ad
from core.tests.fixtures.troubleshooting_runbooks import scenarios as S

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
ACTOR = repo.Actor("alice", "user", tenant="acme")
NAME, IP, OLD = "app.lab", "10.2.2.20", "10.2.2.99"
R1, R2, NS1, NS2 = "10.0.0.53", "10.0.0.54", "ns1", "ns2"
GW = {"live": False, "fixture_id": "simulated-dns", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-1", "source_type": "DNS_QUERY", "transport": "t", "adapter": "a", "command_or_api": "dns:query", "collected_at": T0.isoformat(), "raw_ref": {"hash": "h"}}


def rr(name, rtype, data, ttl=300):
    return {"name": name, "type": rtype, "ttl": ttl, "data": data}


def soa_row(serial, ttl=3600, minimum=60, name="lab"):
    return rr(name, "SOA", f"ns1.lab hostmaster.lab {serial} 7200 900 1209600 {minimum}", ttl)


def doc(req, **kw):
    """Response document for a request dict; ``kw`` overrides top-level fields."""
    op = req["op"]
    base = {"schema": nz.DNS_SCHEMA, "op": op, "status": "response"}
    if op in ("query", "soa"):
        base.update(server=req["server"], server_role=req["role"], name=req["name"] if op == "query" else req["zone"], qtype=req["qtype"] if op == "query" else "SOA",
                    transport=req["transport"], rcode="NOERROR", flags={"aa": req["role"] == "authoritative", "rd": True, "ra": req["role"] == "recursive"}, answers=[], authority=[])
    base.update(kw)
    return json.dumps(base)


def qreq(role="recursive", server=R1, name=NAME, qtype="A", transport="udp", op="query", zone=""):
    return {"op": op, "server": server, "name": name, "zone": zone, "qtype": qtype, "role": role, "transport": transport}


def norm(raw, request, **kw):
    return nz.normalize_dns(raw, request=request, device="c1", evidence=EV, now=T0, observed_at=T0, **kw)


class World:
    """Scriptable DNS world behind an injected runner.  ``calls`` records every request the collector made (nothing else touches a network)."""

    def __init__(self, *, auth_data=None, rec_data=None, rec_ttl=None, serials=None, xfr=None, refused=(), tcp_down=(), timeouts=(), garbage=(), dnssec=None, time_sync=None,
                 delegation_lame=(), records=None, resolver_config=None, provenance=None):
        self.auth_data = auth_data or {NS1: IP, NS2: IP}
        self.rec_data = rec_data or {R1: IP, R2: IP}
        self.rec_ttl = rec_ttl or {R1: 120, R2: 120}
        self.serials = serials or {NS1: 2026110901, NS2: 2026110901}
        self.xfr = xfr or {NS2: "ok"}
        self.refused, self.tcp_down, self.timeouts, self.garbage = set(refused), set(tcp_down), set(timeouts), set(garbage)
        self.dnssec, self.time_sync, self.delegation_lame = dnssec, time_sync or {"synchronized": True, "offset_ms": 3, "source": "chrony"}, set(delegation_lame)
        self.records, self.resolver_config = records, resolver_config or {"nameservers": [R1, R2], "search": ["lab"]}
        self.calls: list[dict] = []
        if provenance:
            self.provenance = lambda: provenance

    def execute(self, req):
        self.calls.append(req)
        assert req["read_only"] is True and req["schema"] == "nmas.dns.request/1"
        op, server = req["op"], req.get("server")
        if server in self.timeouts and op != "zone_status":
            raise TimeoutError("runner timeout")
        if server in self.garbage:
            return "{definitely not json"
        if op == "resolver_config":
            return doc(req, nameservers=self.resolver_config["nameservers"], search=self.resolver_config["search"])
        if op == "transport":
            att = [{"transport": "udp", "status": "response", "rcode": "REFUSED" if server in self.refused else "NOERROR"},
                   {"transport": "tcp", "status": "timeout" if server in self.tcp_down else "response", "rcode": "REFUSED" if server in self.refused else "NOERROR"}]
            return doc(req, server=server, attempts=[a if a["status"] == "response" else {"transport": a["transport"], "status": a["status"]} for a in att])
        if op == "query":
            if server in self.refused:
                return doc(req, rcode="REFUSED")
            data = (self.rec_data if req["role"] == "recursive" else self.auth_data)[server]
            ttl = self.rec_ttl[server] if req["role"] == "recursive" else 300
            return doc(req, answers=[rr(NAME, "A", data, ttl)])
        if op == "soa":
            return doc(req, answers=[soa_row(self.serials[server])])
        if op == "zone_status":
            return doc(req, server=server, zone=req["zone"], last_result=self.xfr.get(server, "ok"), serial=self.serials[server])
        if op == "delegation":
            return doc(req, zone=req["zone"], servers=[{"ns": n, "status": "response", "rcode": "REFUSED" if n in self.delegation_lame else "NOERROR", "aa": n not in self.delegation_lame}
                                                       for n in (NS1, NS2)])
        if op == "records":
            sec = lambda rows: {"status": "response", "rcode": "NOERROR", "rows": rows}
            return doc(req, name=NAME, **(self.records or {"a": sec([rr(NAME, "A", IP)]), "aaaa": sec([]), "cname": sec([]), "ptr": sec([rr("20.2.2.10.in-addr.arpa", "PTR", NAME)])}))
        if op == "dnssec":
            return doc(req, zone=req["zone"], **(self.dnssec or {"ad": None}))
        if op == "time_sync":
            return doc(req, **self.time_sync)
        raise AssertionError(op)


class UnitParserTests(SimpleTestCase):
    def test_DNSSRC_001_authoritative_and_recursive_answers_are_distinguished(self):
        auth = norm(doc(qreq("authoritative", NS1), answers=[rr(NAME, "A", IP, 300)]), qreq("authoritative", NS1))
        rec = norm(doc(qreq("recursive", R1), answers=[rr(NAME, "A", IP, 120)], original_ttl=300, cache="hit"), qreq("recursive", R1))
        (a,), (r,) = auth["observations"], rec["observations"]
        self.assertEqual(a["target"]["dns"], f"{NAME}/{NS1}")
        self.assertEqual((a["value"]["role"], a["value"]["aa"], a["value"]["ttl"], a["value"]["answers"]), ("authoritative", True, 300, [IP]))
        self.assertEqual((r["value"]["role"], r["value"]["aa"], r["value"]["ttl"], r["value"]["cache"], r["value"]["cache_age_s"]), ("recursive", False, 120, "hit", 180))
        self.assertEqual(r["value"]["expires_at"], "2026-11-09T12:02:00Z")
        self.assertEqual((rec["parser"]["id"], rec["parser"]["version"]), ("dns.response", "dns-json-1.0"))

    def test_DNSSRC_002_soa_serial_and_invalid_soa(self):
        req = {"op": "soa", "server": NS1, "zone": "lab", "role": "authoritative", "transport": "udp", "name": "", "qtype": ""}
        (o,) = norm(doc(req, answers=[soa_row(4294967295)]), req)["observations"]
        self.assertEqual((o["value"]["serial"], o["value"]["minimum"], o["value"]["mname"]), (4294967295, 60, "ns1.lab"))
        for bad in (soa_row(-1), rr("lab", "SOA", "ns1.lab host 12 7200"), rr("lab", "SOA", "ns1.lab host 4294967296 1 1 1 1")):
            res = norm(doc(req, answers=[bad]), req)
            self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], "PARSE_FAILED"))
        res = norm(doc(req, rcode="REFUSED"), req)
        self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], "EMPTY"))
        self.assertEqual(res["missing"][0]["extra"]["engine_key"], "dns.soa@lab/ns1")

    def test_DNSSRC_003_negative_caching_ttl(self):
        req = qreq("recursive", R1)
        (o,) = norm(doc(req, rcode="NXDOMAIN", authority=[soa_row(5, ttl=900, minimum=60)]), req)["observations"]
        self.assertEqual((o["value"]["negative"], o["value"]["ttl"], o["value"]["answers"]), (True, 60, []))
        (o,) = norm(doc(req, rcode="NOERROR", authority=[soa_row(5, ttl=30, minimum=600)]), req)["observations"]
        self.assertEqual((o["value"]["negative"], o["value"]["ttl"]), (True, 30))
        (o,) = norm(doc(req, rcode="NOERROR"), req)["observations"]          # NODATA without SOA: negative TTL unknowable, never 0
        self.assertEqual((o["quality"], o["value"]["ttl"]), ("UNTRUSTED_PARSE", None))
        (o,) = norm(doc(req, rcode="SERVFAIL"), req)["observations"]
        self.assertEqual((o["value"]["rcode"], o["value"]["ttl"], o["quality"]), ("SERVFAIL", 0, "OK"))

    def test_DNSSRC_004_response_for_another_question_is_never_attributed(self):
        req = qreq("recursive", R1)
        for override in ({"name": "other.lab"}, {"server": R2}, {"qtype": "AAAA"}, {"transport": "tcp"}, {"server_role": "authoritative"}, {"rcode": "BOGUS"},
                         {"schema": "something/else"}, {"op": "soa"}, {"flags": {"aa": "yes"}}):
            res = norm(doc(req, **override), req)
            self.assertEqual(res["observations"], [], override)
            self.assertEqual(res["missing"][0]["reason"], "PARSE_FAILED", override)
            self.assertEqual(res["missing"][0]["extra"]["engine_key"], f"dns.query@{NAME}/{R1}")

    def test_DNSSRC_005_malformed_rows_and_documents(self):
        req = qreq("recursive", R1)
        for rows in ([rr(NAME, "A", "999.1.1.1")], [rr(NAME, "A", IP, -1)], [rr(NAME, "A", IP, True)], [rr(NAME, "A", "2001:db8::1")], [rr(NAME, "AAAA", IP)], ["x"],
                     [rr("bad name", "A", IP)], [rr(NAME, "MX", "x")], [rr(NAME, "CNAME", "a.lab"), rr(NAME, "CNAME", "b.lab")], [rr(NAME, "A", IP)] * 65):
            self.assertEqual(norm(doc(req, answers=rows), req)["observations"], [], rows[:1])
        for raw in ("", "[]", "null", "{bad", json.dumps({"schema": nz.DNS_SCHEMA})):
            self.assertEqual(norm(raw, req)["missing"][0]["reason"], "PARSE_FAILED", raw)

    def test_DNSSRC_006_cname_chain_loop_and_final_rrset(self):
        req = qreq("recursive", R1)
        (o,) = norm(doc(req, answers=[rr(NAME, "CNAME", "web.lab", 60), rr("web.lab", "A", IP, 30), rr("noise.lab", "A", OLD, 5)]), req)["observations"]
        self.assertEqual((o["value"]["answers"], o["value"]["ttl"], o["value"]["cname_chain"]), ([IP], 30, ["web.lab"]))
        (o,) = norm(doc(req, answers=[rr(NAME, "CNAME", "b.lab"), rr("b.lab", "CNAME", NAME)]), req)["observations"]
        self.assertTrue(o["value"]["cname_loop"])
        self.assertIn("DNS_CNAME_LOOP", o["flags"])

    def test_DNSSRC_007_timeout_and_error_status_are_gaps(self):
        req = qreq("recursive", R1)
        for status, reason in (("timeout", "TIMEOUT"), ("unreachable", "TRANSPORT_ERROR"), ("error", "TRANSPORT_ERROR")):
            res = norm(doc(req, status=status), req)
            self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], reason))

    def test_DNSSRC_008_transport_attempts(self):
        req = {"op": "transport", "server": R1, "name": "", "zone": "", "qtype": "", "role": "", "transport": "udp"}
        (o,) = norm(doc(req, server=R1, attempts=[{"transport": "udp", "status": "response", "rcode": "NOERROR"}, {"transport": "tcp", "status": "timeout"}]), req)["observations"]
        self.assertEqual((o["value"]["udp_ok"], o["value"]["tcp_ok"], o["value"]["acl_refused"], o["quality"]), (True, False, False, "OK"))
        (o,) = norm(doc(req, server=R1, attempts=[{"transport": "udp", "status": "response", "rcode": "REFUSED"}, {"transport": "tcp", "status": "response", "rcode": "REFUSED"}]), req)["observations"]
        self.assertEqual((o["value"]["udp_ok"], o["value"]["acl_refused"]), (False, True))
        (o,) = norm(doc(req, server=R1, attempts=[{"transport": "udp", "status": "response", "rcode": "NOERROR"}]), req)["observations"]     # TCP never tried
        self.assertEqual((o["value"]["tcp_ok"], o["quality"]), (None, "UNTRUSTED_PARSE"))

    def test_DNSSRC_009_dnssec_unavailable_is_a_gap_not_a_verdict(self):
        req = {"op": "dnssec", "server": R1, "zone": "lab", "name": "", "qtype": "", "role": "", "transport": "udp"}
        res = norm(doc(req, zone="lab", ad=None), req)
        self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], "EMPTY"))
        res = norm(doc(req, zone="lab", ad=True, rrsig={"expiration": "2026-12-01T00:00:00Z"}), req)           # AD but no DS evidence
        self.assertEqual(res["observations"], [])
        (o,) = norm(doc(req, zone="lab", ad=True, rrsig={"expiration": "2026-11-12T13:00:00Z"}, ds={"match": True}), req)["observations"]
        self.assertEqual((o["value"]["ad"], o["value"]["rrsig_days_left"], o["value"]["ds_match"]), (True, 3, True))
        (o,) = norm(doc(req, zone="lab", ad=False, validation="bogus"), req)["observations"]
        self.assertEqual((o["value"]["ad"], "rrsig_days_left" in o["value"]), (False, False))

    def test_DNSSRC_010_records_and_time_sync(self):
        req = {"op": "records", "name": NAME, "server": "", "zone": "", "qtype": "", "role": "", "transport": "udp", "aaaa_expected": True}
        sec = lambda rows, rc="NOERROR": {"status": "response", "rcode": rc, "rows": rows}
        good = dict(a=sec([rr(NAME, "A", IP)]), aaaa=sec([]), cname=sec([]), ptr=sec([rr("20.2.2.10.in-addr.arpa", "PTR", NAME)]))
        (o,) = norm(doc(req, name=NAME, **good), req)["observations"]
        self.assertEqual((o["value"]["a"], o["value"]["ptr"], o["value"]["aaaa"], o["value"]["aaaa_expected"], o["quality"]), ([IP], NAME, [], True, "OK"))
        (o,) = norm(doc(req, name=NAME, **{**good, "aaaa": {"status": "timeout"}}), req)["observations"]                # unknown AAAA must not read as "missing AAAA"
        self.assertEqual(o["quality"], "UNTRUSTED_PARSE")
        tr = {"op": "time_sync", "server": "", "name": "", "zone": "", "qtype": "", "role": "", "transport": "udp"}
        self.assertEqual(norm(doc(tr, synchronized=False, offset_ms=None), tr)["missing"][0]["reason"], "EMPTY")
        self.assertEqual(norm(doc(tr, synchronized=True, offset_ms=7000.0, source="chrony"), tr)["observations"][0]["value"]["offset_ms"], 7000.0)


class CollectorTests(SimpleTestCase):
    TARGET = col.Target(device="c1", platform="linux", verified=True, lifecycle_state="VERIFIED")

    def collector(self, **budget):
        return col.DnsCollector(budget=col.Budget(**budget) if budget else None, sleep=lambda s: None, now=lambda: T0, capability_probe=lambda *a: {"status": "UNKNOWN"})

    def test_DNSSRC_011_validation_blocks_before_the_runner(self):
        w = World()
        bad = [col.DnsRequest("query", server=R1, name="x" * 64 + ".lab", qtype="A", role="recursive"), col.DnsRequest("query", server=R1, name=NAME, qtype="AXFR", role="recursive"),
               col.DnsRequest("query", server=R1, name=NAME, qtype="ANY", role="recursive"), col.DnsRequest("query", server="203.0.113.9", name=NAME, qtype="A", role="recursive"),
               col.DnsRequest("query", server="224.0.0.251", name=NAME, qtype="A", role="recursive"), col.DnsRequest("query", server=R1, name="a b.lab", qtype="A", role="recursive"),
               col.DnsRequest("query", server=R1, name="*.lab", qtype="A", role="recursive"), col.DnsRequest("query", server=R1, name=NAME, qtype="A", role="authoritative-ish"),
               col.DnsRequest("axfr", server=R1, zone="lab"), col.DnsRequest("query", server=R1, name=NAME, qtype="A", role="recursive", transport="icmp"),
               col.DnsRequest("query", server=R1, name="", qtype="A", role="recursive")]
        bundle = self.collector().collect(self.TARGET, bad, w, allowed_servers=[R1, R2, NS1, NS2])
        self.assertEqual(w.calls, [])
        self.assertEqual([r["reason"] for r in bundle["missing"]], ["COMMAND_NOT_ALLOWED"] * len(bad))
        self.assertEqual(bundle["observations"], [])

    def test_DNSSRC_012_normalised_request_and_names(self):
        req, err = col.DnsRequest("query", server="2001:0DB8:0:0:0:0:0:53", name="App.Lab.", qtype="a", role="recursive").validate()
        self.assertEqual((err, req.name, req.server, req.qtype), ([], "app.lab", "2001:db8::53", "A"))
        self.assertEqual(req.engine_key(), "dns.query@app.lab/2001:db8::53")

    def test_DNSSRC_013_budget_retry_and_size_bounds(self):
        reqs = [col.DnsRequest("query", server=s, name=NAME, qtype="A", role="recursive") for s in (R1, R2, R1)]
        w = World()
        bundle = self.collector(max_commands=2).collect(self.TARGET, reqs[:2] + [col.DnsRequest("time_sync")], w)
        self.assertEqual(len(w.calls), 2)
        self.assertEqual([r["reason"] for r in bundle["missing"]], ["BUDGET_EXCEEDED"])
        self.assertEqual(bundle["missing"][0]["extra"]["engine_key"], "time.sync")
        flaky = World(timeouts=[R1])
        bundle = self.collector(max_retries=1).collect(self.TARGET, reqs[:1], flaky)
        self.assertEqual((len(flaky.calls), bundle["missing"][0]["reason"], bundle["run"]["retries"]), (2, "TIMEOUT", 1))

        class Huge:
            def execute(self, request):
                return " " * (col.DNS_MAX_RESPONSE_BYTES + 1)
        bundle = self.collector().collect(self.TARGET, reqs[:1], Huge())
        self.assertEqual((bundle["observations"], bundle["missing"][0]["reason"]), ([], "OUTPUT_TOO_LARGE"))

        class Denied:
            def execute(self, request):
                raise col.PermissionDenied()
        self.assertEqual(self.collector().collect(self.TARGET, reqs[:1], Denied())["missing"][0]["reason"], "PERMISSION_DENIED")

    def test_DNSSRC_014_truncated_udp_retries_once_over_tcp(self):
        class Trunc:
            def __init__(self):
                self.calls = []

            def execute(self, request):
                self.calls.append(request["transport"])
                if request["transport"] == "udp":
                    return doc(request, flags={"aa": False, "tc": True, "ra": True}, answers=[rr(NAME, "A", IP)])
                return doc(request, answers=[rr(NAME, "A", IP), rr(NAME, "A", OLD)])
        r = Trunc()
        bundle = self.collector().collect(self.TARGET, [col.DnsRequest("query", server=R1, name=NAME, qtype="A", role="recursive")], r)
        self.assertEqual(r.calls, ["udp", "tcp"])
        (o,) = bundle["observations"]
        self.assertEqual((o["value"]["transport"], o["value"]["answers"], o["quality"]), ("tcp", sorted([IP, OLD]), "OK"))
        self.assertEqual(len(bundle["evidence"]), 2)                      # the truncated raw answer stays as evidence
        self.assertTrue(any(f.startswith("DNS_UDP_TRUNCATED") for f in bundle["run"]["flags"]))

    def test_DNSSRC_015_unverified_device_never_reaches_the_runner(self):
        w = World()
        bundle = self.collector().collect(col.Target(device="c1", platform="linux", verified=False, lifecycle_state="UNVERIFIED"), [col.DnsRequest("time_sync")], w)
        self.assertEqual((w.calls, bundle["run"]["status"], bundle["missing"][0]["reason"]), ([], "REFUSED", "NOT_ADMITTED"))


# ------------------------------------------------------------------------------------------------------------------ runtime -> RB05
def make_case(key):
    devs = ["c1", NS1, NS2]
    return repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "dns", "target": S.RB05_TARGET},
                          flow_scope={}, affected_scope={"devices": devs}, target_states={d: "VERIFIED" for d in devs}, severity="HIGH", runbook="RB05", worked_before=True,
                          first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))


def deps(world, *, at=T0, context=None, runner=True):
    return rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {d: {"platform": "linux", "os_version": "5.15"} for d in ("c1", NS1, NS2)}),
        dns_runner=(lambda info: world) if runner else None, dns_context=context, sources=bl.StaticSources({**S.static_data(), "intent": S.rb05_intent()}),
        clock=lambda: 0.0, sleep=lambda s: None, now=lambda: at, capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})


def run(key, world, *, target=None, **kw):
    case = make_case(key)
    if target:
        case.service_intent = {"service": "dns", "target": {**S.RB05_TARGET, **target}}
        case.save()
    res = rt.run_case(ACTOR, case.case_id, deps(world, **kw), run_key="r1", now=kw.get("at", T0), engine_config=eng.EngineConfig(exhaustive=True))
    return case, res


def verdicts(case):
    return {t.test_id: t.verdict for t in m.TsDiagnosticTest.objects.filter(case=case)}


def obs(case, key, device="c1", **kw):
    return m.TsObservation.objects.get(case=case, target=device, key=key, **kw)


class RuntimeToRb05Tests(TestCase):
    def test_DNSSRC_016_healthy_end_to_end_with_provenance(self):
        w = World(provenance=GW)
        case, res = run("d16", w)
        v = verdicts(case)
        self.assertEqual({v[t] for t in ("DN01", "DN02", "DN03", "DN04", "DN05", "DN06", "DN07", "DN10")}, {"PASS"}, v)
        self.assertEqual(v["DN09"], "SKIPPED")
        self.assertEqual(v["DN08"], "SKIPPED")
        self.assertTrue(all(c["op"] != "axfr" for c in w.calls))
        self.assertLessEqual(len(w.calls), 16 + 4)
        row = obs(case, f"dns.query@{NAME}/{R1}", is_missing_data=False)
        self.assertEqual((row.value["role"], row.value["answers"], row.value["ttl"]), ("recursive", [IP], 120))
        ev = m.TsEvidenceRef.objects.get(case=case, device="c1", command_or_api=f"dns:query name={NAME} type=A server={NS1} proto=udp")
        self.assertEqual((ev.parser, ev.parser_version, ev.source_type), ("dns.response", "dns-json-1.0", "dns_query"))
        self.assertEqual(ev.scope["gateway"], GW)
        self.assertFalse(ev.scope["live"])
        self.assertRegex(ev.scope["raw_hash_as_received"], r"^(sha256:)?[0-9a-f]{64}$")
        self.assertEqual(obs(case, f"dns.soa@lab/{NS1}", is_missing_data=False).value["serial"], 2026110901)

    def test_DNSSRC_017_authoritative_mismatch_and_zone_propagation(self):
        w = World(auth_data={NS1: IP, NS2: OLD}, serials={NS1: 2026110901, NS2: 2026110800}, xfr={NS2: "REFUSED (TSIG key mismatch)"})
        case, res = run("d17", w)
        v = verdicts(case)
        self.assertEqual((v["DN04"], v["DN05"]), ("FAIL", "FAIL"), v)
        self.assertIn("F-zone-propagation", json.dumps(res["diagnosis"]))
        self.assertIn("F-auth-inconsistent", json.dumps(res["diagnosis"]))
        self.assertEqual(obs(case, "dns.xfr@lab", device=NS2, is_missing_data=False).value["last_result"], "REFUSED (TSIG key mismatch)")
        self.assertTrue([c for c in w.calls if c["op"] == "zone_status" and c["server"] == NS2])
        self.assertFalse([c for c in w.calls if c["op"] == "zone_status" and c["server"] not in (NS1, NS2)])

    def test_DNSSRC_018_stale_cache_then_ttl_aware_recovery(self):
        stale = World(rec_data={R1: IP, R2: OLD}, rec_ttl={R1: 120, R2: 240})
        case, res = run("d18a", stale)
        v = verdicts(case)
        self.assertEqual((v["DN04"], v["DN05"], v["DN06"]), ("PASS", "PASS", "FAIL"), v)
        self.assertIn("F-cache-ttl", json.dumps(res["diagnosis"]))
        row = obs(case, f"dns.query@{NAME}/{R2}", is_missing_data=False)
        self.assertEqual((row.value["answers"], row.value["ttl"], row.value["expires_at"]), ([OLD], 240, "2026-11-09T12:04:00Z"))
        rec = dns_ad.ttl_recovery(row.value, row.observed_at, T0 + timedelta(seconds=100))
        self.assertEqual((rec["state"], rec["remaining_s"], rec["recheck_at"]), ("WAITING_TTL", 140, "2026-11-09T12:04:00Z"))
        self.assertEqual(dns_ad.ttl_recovery(row.value, row.observed_at, T0 + timedelta(seconds=241))["state"], "RECHECK_DUE")
        # after the TTL window the resolver re-fetched from the (correct) authoritative server
        later = T0 + timedelta(seconds=241)
        case2, _ = run("d18b", World(), at=later)
        self.assertEqual(verdicts(case2)["DN06"], "PASS")
        self.assertEqual(obs(case2, f"dns.query@{NAME}/{R2}", is_missing_data=False).value["answers"], [IP])

    def test_DNSSRC_019_policy_and_transport_failures(self):
        case, res = run("d19a", World(refused=[R2]))
        v = verdicts(case)
        self.assertEqual((v["DN02"], v["DN03"]), ("FAIL", "FAIL"), v)
        self.assertIn("F-dns-transport", json.dumps(res["diagnosis"]))
        self.assertEqual(obs(case, f"dns.query@{NAME}/{R2}", is_missing_data=False).value["rcode"], "REFUSED")
        case, res = run("d19b", World(tcp_down=[R1]))
        row = obs(case, f"dns.transport@{R1}", is_missing_data=False)
        self.assertEqual((row.value["udp_ok"], row.value["tcp_ok"], row.value["acl_refused"]), (True, False, False))
        self.assertEqual(verdicts(case)["DN02"], "FAIL")

    def test_DNSSRC_020_malformed_timeout_and_unavailable_runner_never_pass(self):
        case, _ = run("d20a", World(garbage=[R1]))
        v = verdicts(case)
        self.assertTrue(obs(case, f"dns.query@{NAME}/{R1}", is_missing_data=True).missing_reason.startswith("PARSE_FAILED"))
        self.assertNotIn("PASS", {v["DN02"], v["DN03"]}, v)
        self.assertFalse(m.TsObservation.objects.filter(case=case, key=f"dns.query@{NAME}/{R1}", is_missing_data=False).exists())
        case, _ = run("d20b", World(timeouts=[R2]))
        self.assertTrue(obs(case, f"dns.query@{NAME}/{R2}", is_missing_data=True).missing_reason.startswith("TIMEOUT"))
        self.assertNotIn(verdicts(case)["DN03"], ("PASS", "FAIL"))
        case, _ = run("d20c", World(), runner=False)
        v = verdicts(case)
        self.assertTrue(obs(case, f"dns.query@{NAME}/{R1}", is_missing_data=True).missing_reason.startswith("NOT_CONFIGURED"))
        self.assertEqual({v[t] for t in ("DN01", "DN02", "DN03", "DN04", "DN05", "DN06", "DN07")} & {"PASS", "FAIL"}, set(), v)

    def test_DNSSRC_021_dnssec_unavailable_vs_failure_vs_valid(self):
        case, _ = run("d21a", World(), target={"dnssec": True})
        self.assertNotIn(verdicts(case)["DN09"], ("PASS", "FAIL", "SKIPPED"))
        self.assertTrue(obs(case, "dns.dnssec@lab", is_missing_data=True).missing_reason.startswith("EMPTY"))
        case, _ = run("d21b", World(dnssec={"ad": False, "validation": "bogus"}), target={"dnssec": True})
        self.assertEqual(verdicts(case)["DN09"], "FAIL")
        ok = {"ad": True, "rrsig": {"expiration": "2026-12-01T00:00:00Z"}, "ds": {"match": True}}
        case, _ = run("d21c", World(dnssec=ok), target={"dnssec": True})
        self.assertEqual(verdicts(case)["DN09"], "PASS")

    def test_DNSSRC_022_client_config_lame_delegation_and_time_skew(self):
        case, _ = run("d22a", World(resolver_config={"nameservers": [R1], "search": []}))
        self.assertEqual(verdicts(case)["DN01"], "FAIL")
        case, _ = run("d22b", World(delegation_lame=[NS2]))
        self.assertEqual(verdicts(case)["DN05"], "FAIL")
        case, _ = run("d22c", World(time_sync={"synchronized": True, "offset_ms": 9000, "source": "chrony"}))
        self.assertEqual(verdicts(case)["DN10"], "FAIL")
        case, _ = run("d22d", World(time_sync={"synchronized": False, "offset_ms": None, "source": ""}))
        self.assertTrue(obs(case, "time.sync", is_missing_data=True).missing_reason.startswith("EMPTY"))

    def test_DNSSRC_023_split_horizon_vantage_servers_are_explicit(self):
        reqs = dns_ad.requests_for_device(S.RB05_TARGET, "c1", {"dns.query", "dns.soa", "dns.dnssec", "dns.xfr"}, None)
        self.assertEqual([(r.op, r.server) for r in reqs], [("query", R1), ("query", R2), ("query", NS1), ("query", NS2), ("soa", NS1), ("soa", NS2), ("delegation", "")])
        self.assertEqual(dns_ad.requests_for_device(S.RB05_TARGET, "ns1", {"dns.xfr", "dns.query"}, None)[0].op, "zone_status")
        self.assertEqual(dns_ad.requests_for_device(S.RB05_TARGET, "other", {"dns.query", "dns.xfr"}, None), [])
        ctx = dns_ad.DnsContext(vantage_servers={"c9": ["10.9.9.53"]})
        self.assertEqual([(r.op, r.server) for r in dns_ad.requests_for_device(S.RB05_TARGET, "c9", {"dns.query"}, ctx)], [("query", "10.9.9.53")])
        self.assertIn("10.9.9.53", dns_ad.allowed_servers(S.RB05_TARGET, ctx))

    def test_DNSSRC_024_source_labels(self):
        self.assertEqual(dns_ad.describe_source()["label"], "SIMULATED")
        self.assertEqual(dns_ad.describe_source(recorded=True)["label"], "RECORDED")
        self.assertFalse(dns_ad.describe_source(gateway={"live": "true"})["live"])
        self.assertTrue(dns_ad.describe_source(gateway={"live": True})["live"])
