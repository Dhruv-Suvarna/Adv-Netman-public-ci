"""PMTU size-dependent probe source (``path.pmtu``, HC21 / RB06 MT03/MT05) -- contract -> collector -> runtime -> runbook.  Stable IDs PMTUSRC-001 .. PMTUSRC-024.

PROVENANCE: every runner response below is SIMULATED (hand-written ``nmas.probe.response/1``).  No gateway-recorded output is pinned, no socket is opened and nothing
here claims live verification or real TCP behaviour.
"""

from __future__ import annotations

import json
from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting.adapters import probes as pr
from core.services.troubleshooting.runbooks.hc import pmtu_assess
from core.tests.fixtures.troubleshooting_runbooks import scenarios as S
from core.tests.test_troubleshooting_probe_source import (ADDR, CTX_KW, FLOW, GW, T0, TARGET, ACTOR, collector, deps, go, iso, make_case, reasons, tests_of)

LADDER = (548, 1000, 1200, 1400, 1472)
AUTH_OPS = ["pmtu_probe"]


def pctx(ops=AUTH_OPS, **kw):
    ctx = pr.ProbeContext(authorization={"id": "AP-1", "case_id": "C1", "expires_at": iso(T0 + timedelta(hours=1)), "operations": ops}, **{**CTX_KW, "pmtu_protocols": ("icmp",), **kw})
    return pr.policy_for(FLOW, "C1", ctx), ctx


def pmtu_doc(limit=1500, vis="observable", sizes=LADDER, per=2, ptb=False, family="ipv4", protocol="icmp", skip=(), **kw):
    """Simulated runner: packets whose size exceeds ``limit`` are lost (or answered with PTB when ``ptb``)."""
    hdr = pr.overhead(family, protocol)
    rows = []
    for s in sizes:
        if s in skip:
            continue
        for _ in range(per):
            over = s + hdr > limit
            rows.append({"payload_bytes": s, "packet_bytes": s + hdr, "outcome": ("ptb" if ptb else "timeout") if over else "reply", "rtt_ms": None if over else 2.0,
                         "ptb_mtu": limit if over and ptb else None})
    d = {"schema": pr.RESPONSE_SCHEMA, "op": "pmtu_probe", "status": "response", "vantage": {"device": "h1", "address": ADDR["h1"], "kind": "host-namespace"},
         "destination": {"address": ADDR["h2"]}, "protocol": protocol, "family": family, "df": True, "ptb_visibility": vis, "started_at": iso(T0 - timedelta(seconds=6)),
         "finished_at": iso(T0), "trials": rows}
    d.update(kw)
    return json.dumps(d)


class Runner:
    def __init__(self, doc=None, caps=("pmtu_probe",), raises=None):
        self.doc, self.caps, self.raises, self.calls = doc or pmtu_doc(), caps, raises, []

    def capabilities(self):
        return self.caps

    def execute(self, req):
        self.calls.append(req)
        assert req["active_probe"] is True and req["mutating"] is False and req["df"] is True
        if self.raises:
            raise self.raises
        return self.doc

    def provenance(self):
        return GW


def req_for(**kw):
    _, c = pctx()
    r = pr.requests_for_device(FLOW, "h1", ["path.pmtu"], c)[0]
    return col.ProbeRequest(**{**r.__dict__, **kw})


def run(runner, req=None, pol=None, **bk):
    p, c = pctx()
    reqs = [req] if req is not None else pr.requests_for_device(FLOW, "h1", ["path.pmtu"], c)
    return collector(c, **bk).collect(TARGET, reqs, runner, pol or p)


def obs(b):
    return b["observations"][0]


class ContractTests(SimpleTestCase):
    def test_PMTUSRC_001_request_is_a_bounded_df_ladder_from_the_flow_source_only(self):
        _, c = pctx()
        r = pr.requests_for_device(FLOW, "h1", ["path.pmtu"], c)
        self.assertEqual(len(r), 1)
        self.assertEqual((r[0].op, r[0].sizes, r[0].family, r[0].df, r[0].protocol, r[0].count, r[0].engine_key()), ("pmtu_probe", LADDER, "ipv4", True, "icmp", 2, "path.pmtu@h2"))
        self.assertEqual(pr.requests_for_device(FLOW, "r1", ["path.pmtu"], c), [])
        self.assertEqual(pr.requests_for_device(FLOW, "h1", ["path.pmtu"], pr.ProbeContext(**CTX_KW)), [])       # no explicit size-probe opt-in: nothing is requested
        self.assertEqual(pr.requests_for_device(FLOW, "h1", ["path.pmtu"], None), [])
        self.assertEqual(pr.requests_for_device(FLOW, "h1", ["interface.mtu"], c), [])
        _, c2 = pctx(pmtu_required_payload=1200)
        self.assertEqual(pr.requests_for_device(FLOW, "h1", ["path.pmtu"], c2)[0].sizes, (548, 1000, 1200))
        self.assertEqual(pr.requests_for_device({**FLOW, "app_bytes": 900}, "h1", ["path.pmtu"], c)[0].sizes, (548, 900))

    def test_PMTUSRC_002_good_run_separates_payload_from_packet_size_and_claims_no_tcp(self):
        r = Runner()
        b = run(r)
        self.assertEqual(reasons(b), [])
        w = r.calls[0]
        self.assertEqual((w["op"], w["payload_sizes"], w["max_packets"], w["max_packet_bytes"], w["df"], w["protocol"]), ("pmtu_probe", list(LADDER), 10, sum(s + 28 for s in LADDER) * 2, True, "icmp"))
        v = obs(b)["value"]
        self.assertEqual((obs(b)["key"], obs(b)["target"]["probe"], v["max_ok_size"], v["max_ok_packet"], v["header_overhead"], v["complete"], v["packets_sent"]), ("path.pmtu", "h2", 1472, 1500, 28, True, 10))
        self.assertEqual([(t["data_bytes"], t["packet_bytes"]) for t in v["sizes"]][-1], (1472, 1500))
        self.assertEqual((v["tcp_behavior_verified"], v["production_flow_equivalent"], v["ptb_received"]), (False, False, False))
        self.assertTrue(any("TCP production" in x for x in v["limitations"]))
        self.assertEqual((b["run"]["gateway"], b["evidence"][0]["parser"]["id"]), (GW, "probe.pmtu"))

    def test_PMTUSRC_003_ipv6_overhead_is_48_and_family_must_match(self):
        addr = {**ADDR, "h2": "2001:db8::2"}
        _, c = pctx(addresses=addr, destinations=("h2", "2001:db8::2"))
        p = pr.policy_for(FLOW, "C1", c)
        rq = pr.requests_for_device(FLOW, "h1", ["path.pmtu"], c)[0]
        self.assertEqual(rq.family, "ipv6")
        doc = json.loads(pmtu_doc(family="ipv6", limit=1600))
        doc["destination"]["address"] = "2001:db8::2"
        b = collector(c).collect(TARGET, [rq], Runner(json.dumps(doc)), p)
        v = obs(b)["value"]
        self.assertEqual((v["header_overhead"], v["max_ok_packet"]), (48, 1472 + 48))
        # a policy that authorizes IPv4 only refuses the IPv6 destination
        _, c4 = pctx(addresses=addr, destinations=("h2", "2001:db8::2"), pmtu_families=("ipv4",))
        r = Runner()
        b = collector(c4).collect(TARGET, [rq], r, pr.policy_for(FLOW, "C1", c4))
        self.assertEqual((r.calls, reasons(b)), ([], ["COMMAND_NOT_ALLOWED"]))

    def test_PMTUSRC_004_authorization_scope_gates_never_reach_the_runner(self):
        p, c = pctx()
        base = p.__dict__
        cases = {
            "authorization lacks pmtu_probe": (col.ProbePolicy(**{**base, "pmtu_authorized": False}), "PERMISSION_DENIED"),
            "no authorization": (col.ProbePolicy(**{**base, "deny_reason": "none"}), "PERMISSION_DENIED"),
            "expired": (col.ProbePolicy(**{**base, "expires_at": T0}), "PERMISSION_DENIED"),
            "source not admitted": (col.ProbePolicy(**{**base, "admitted_sources": ("x",)}), "COMMAND_NOT_ALLOWED"),
            "destination not authorized": (col.ProbePolicy(**{**base, "destinations": ("other",)}), "COMMAND_NOT_ALLOWED"),
            "protocol not authorized": (col.ProbePolicy(**{**base, "pmtu_protocols": ("udp",)}), "COMMAND_NOT_ALLOWED"),
            "flow differs": (col.ProbePolicy(**{**base, "flow": {**FLOW, "dst": "h3"}}), "COMMAND_NOT_ALLOWED"),
        }
        for name, (pol, want) in cases.items():
            r = Runner()
            b = run(r, pol=pol)
            self.assertEqual((r.calls, b["observations"], set(reasons(b))), ([], [], {want}), name)
        # the generic probe authorization (no "operations") does not enable size probes
        for ops in ([], ["tcp_connect"], None):
            _, c0 = pctx(ops=ops)
            r = Runner()
            b = collector(c0).collect(TARGET, pr.requests_for_device(FLOW, "h1", ["path.pmtu"], c0), r, pr.policy_for(FLOW, "C1", c0))
            self.assertEqual((r.calls, reasons(b)), ([], ["PERMISSION_DENIED"]), ops)
        # other case
        c.authorization = {**c.authorization, "case_id": "OTHER"}
        r = Runner()
        b = collector(c).collect(TARGET, pr.requests_for_device(FLOW, "h1", ["path.pmtu"], c), r, pr.policy_for(FLOW, "C1", c))
        self.assertEqual((r.calls, reasons(b)), ([], ["PERMISSION_DENIED"]))

    def test_PMTUSRC_005_unbounded_or_unsafe_requests_are_refused_before_sending(self):
        bad = {
            "tcp size probe": dict(protocol="tcp"), "no df": dict(df=False), "udp without authorized port": dict(protocol="udp", port=0),
            "empty sizes": dict(sizes=()), "too many sizes": dict(sizes=tuple(range(100, 1100, 100))), "huge payload": dict(sizes=(100, 65000)),
            "duplicate sizes": dict(sizes=(100, 100)), "bool size": dict(sizes=(True, 1400)), "zero trials": dict(count=0), "too many trials": dict(count=50),
            "rate": dict(rate_pps=500), "rate zero": dict(rate_pps=0), "time": dict(max_seconds=3600.0), "does not fit time": dict(max_seconds=1.0),
            "byte budget": dict(sizes=(8000, 8500, 9000), count=3, max_seconds=30.0), "family mismatch": dict(family="ipv6"), "no address": dict(dst_address=""),
        }
        for name, kw in bad.items():
            r = Runner()
            b = run(r, req=req_for(**kw))
            self.assertEqual((r.calls, b["observations"], reasons(b)), ([], [], ["COMMAND_NOT_ALLOWED"]), name)

    def test_PMTUSRC_006_packet_and_request_budget_is_shared_across_requests(self):
        p, c = pctx(max_probes=15)
        r = Runner()
        b = collector(c).collect(TARGET, [req_for(), req_for()], r, pr.policy_for(FLOW, "C1", c))        # 10 packets each, 15 allowed
        self.assertEqual((len(r.calls), reasons(b)), (1, ["BUDGET_EXCEEDED"]))
        _, c2 = pctx(pmtu_max_packet_bytes=12_000)
        r = Runner(pmtu_doc(sizes=(1400,), per=1))
        one = req_for(count=1, sizes=(1400,), max_seconds=10.0)
        b = collector(c2).collect(TARGET, [one] * 9, r, pr.policy_for(FLOW, "C1", c2))                   # 1428 B each; 8 fit 12 000
        self.assertEqual((len(r.calls), set(reasons(b))), (8, {"BUDGET_EXCEEDED"}))

    def test_PMTUSRC_007_runner_failures_are_gaps_without_retry(self):
        for exc, want in ((TimeoutError("x"), "TIMEOUT"), (col.TransportError("conn", True), "TRANSPORT_ERROR"), (col.PermissionDenied(), "PERMISSION_DENIED"), (RuntimeError("tok"), "TRANSPORT_ERROR")):
            r = Runner(raises=exc)
            b = run(r, max_retries=3)
            self.assertEqual((len(r.calls), reasons(b), b["observations"]), (1, [want], []), want)
        r = Runner(caps=("tcp_connect",))
        self.assertEqual((r.calls, reasons(run(r))), ([], ["UNSUPPORTED_OPERATION"]))

    def test_PMTUSRC_008_malformed_or_inconsistent_responses_are_parse_failed_with_raw_kept(self):
        good = json.loads(pmtu_doc())
        def mut(f):
            d = json.loads(pmtu_doc())
            f(d)
            return json.dumps(d)
        bad = {
            "not json": "{nope", "wrong schema": mut(lambda d: d.update(schema="x")), "wrong op": mut(lambda d: d.update(op="path_trace")), "runner error": mut(lambda d: d.update(status="error")),
            "df not set": mut(lambda d: d.update(df=False)), "df missing": mut(lambda d: d.pop("df")),
            "packet confused with payload": mut(lambda d: d["trials"][0].update(packet_bytes=d["trials"][0]["payload_bytes"])),
            "unrequested size": mut(lambda d: d["trials"][0].update(payload_bytes=777, packet_bytes=805)),
            "extra trials": mut(lambda d: d["trials"].append(dict(d["trials"][0]))), "unknown outcome": mut(lambda d: d["trials"][0].update(outcome="weird")),
            "ptb without mtu": mut(lambda d: d["trials"][-1].update(outcome="ptb", rtt_ms=None)),
            "ptb mtu above packet": mut(lambda d: d["trials"][-1].update(outcome="ptb", rtt_ms=None, ptb_mtu=9000)),
            "mtu without ptb": mut(lambda d: d["trials"][0].update(ptb_mtu=1400)),
            "bad visibility": mut(lambda d: d.update(ptb_visibility="yes")), "protocol mismatch": mut(lambda d: d.update(protocol="udp")), "family mismatch": mut(lambda d: d.update(family="ipv6")),
            "vantage mismatch": mut(lambda d: d["vantage"].update(device="jump")), "destination mismatch": mut(lambda d: d["destination"].update(address="10.9.9.9")),
            "exceeds time budget": mut(lambda d: d.update(finished_at=iso(T0 + timedelta(minutes=10)))), "negative rtt": mut(lambda d: d["trials"][0].update(rtt_ms=-1)),
            "no trials": mut(lambda d: d.update(trials=[])),
        }
        self.assertTrue(good["trials"])
        for name, raw in bad.items():
            b = run(Runner(raw))
            self.assertEqual((b["observations"], reasons(b)), ([], ["PARSE_FAILED"]), name)
            self.assertEqual(len(b["evidence"]), 1, name)

    def test_PMTUSRC_009_missing_large_size_trials_are_incomplete_coverage_not_a_pass(self):
        b = run(Runner(pmtu_doc(skip=(1472,))))                 # the runner silently dropped the service-size trials
        o = obs(b)
        v = o["value"]
        self.assertEqual((o["quality"], v["complete"], v["largest_tested_size"], v["max_ok_size"], "PMTU_COVERAGE_INCOMPLETE" in o["flags"]), ("PARTIAL", False, 1400, 1400, True))
        a = pmtu_assess(v, 1472)
        self.assertEqual(a["state"], "UNKNOWN")
        self.assertIn("UNKNOWN", a["reason"])
        v2 = obs(run(Runner(pmtu_doc(limit=100, per=1, sizes=LADDER[:1], skip=()))))["value"]       # only a loss at a SMALL size: nothing says the service size
        self.assertEqual(pmtu_assess(v2, 1472)["state"], "UNKNOWN")

    def test_PMTUSRC_010_local_errors_are_excluded_and_never_count_as_replies_or_loss(self):
        d = json.loads(pmtu_doc())
        for t in d["trials"]:
            if t["payload_bytes"] == 1472:
                t.update(outcome="local_too_big", rtt_ms=None)           # local EMSGSIZE: says something about the first hop interface only
        o = obs(run(Runner(json.dumps(d))))
        row = [t for t in o["value"]["sizes"] if t["data_bytes"] == 1472][0]
        self.assertEqual((row["status"], row["local_errors"], o["value"]["complete"], pmtu_assess(o["value"], 1472)["state"]), ("unknown", 2, False, "UNKNOWN"))

    def test_PMTUSRC_011_loss_with_unknown_or_invisible_ptb_is_not_a_confirmed_black_hole(self):
        for vis in ("unknown", "not_observable"):
            v = obs(run(Runner(pmtu_doc(limit=1400, vis=vis))))["value"]
            a = pmtu_assess(v, 1472)
            self.assertEqual((a["state"], v["max_ok_size"], v["min_fail_size"], v["ptb_visibility"]), ("LOSS_UNCONFIRMED", 1200, 1400, vis))
            self.assertIn("NOT confirmed", a["reason"])

    def test_PMTUSRC_012_observable_ptb_silence_with_df_loss_is_a_black_hole(self):
        v = obs(run(Runner(pmtu_doc(limit=1400, vis="observable"))))["value"]
        a = pmtu_assess(v, 1472)
        self.assertEqual((a["state"], v["ptb_received"], v["max_ok_packet"]), ("BLACKHOLE", False, 1228))

    def test_PMTUSRC_013_received_ptb_means_pmtud_signalling_works_not_a_black_hole(self):
        v = obs(run(Runner(pmtu_doc(limit=1400, vis="unknown", ptb=True))))["value"]
        a = pmtu_assess(v, 1472)
        self.assertEqual((a["state"], v["ptb_received"], v["ptb_mtu"], v["ptb_visibility"]), ("LIMIT", True, 1400, "observed"))

    def test_PMTUSRC_014_intermittent_or_non_monotonic_loss_is_not_size_dependent_evidence(self):
        d = json.loads(pmtu_doc())
        d["trials"][-1].update(outcome="timeout", rtt_ms=None)           # one of two big probes lost
        o = obs(run(Runner(json.dumps(d))))
        self.assertEqual((o["quality"], pmtu_assess(o["value"], 1472)["state"], "PMTU_NON_MONOTONIC" in o["flags"]), ("PARTIAL", "UNKNOWN", True))
        d = json.loads(pmtu_doc(limit=1400))                              # a bigger size answered while a smaller one was lost
        for t in d["trials"]:
            if t["payload_bytes"] == 1472:
                t.update(outcome="reply", rtt_ms=2.0)
        o = obs(run(Runner(json.dumps(d))))
        self.assertEqual((o["value"]["monotonic"], pmtu_assess(o["value"], 1472)["state"]), (False, "UNKNOWN"))

    def test_PMTUSRC_015_legacy_untyped_values_keep_their_rule_and_typed_pass_requires_a_big_reply(self):
        self.assertEqual(pmtu_assess({"max_ok": 1372, "ptb_received": False}, 1472)["state"], "BLACKHOLE")
        self.assertEqual(pmtu_assess({"max_ok": 1472}, 1472)["state"], "OK")
        self.assertFalse(pmtu_assess({"max_ok": 1472}, 1472)["typed"])
        v = obs(run(Runner()))["value"]
        self.assertEqual((pmtu_assess(v, 1472)["state"], pmtu_assess(v, 1473)["state"]), ("OK", "UNKNOWN"))        # a bigger need than the ladder tested is UNKNOWN
        self.assertEqual(pmtu_assess({**v, "df": False}, 1472)["state"], "UNKNOWN")

    def test_PMTUSRC_016_source_description_lists_the_pmtu_parser(self):
        self.assertEqual(pr.describe_source()["parsers"]["pmtu_probe"]["id"], "probe.pmtu")
        self.assertEqual(pr.describe_source()["label"], "SIMULATED")


# ------------------------------------------------------------------------------------------------------------------ runtime -> HC21 / RB06
def pm_deps(runner, case, **kw):
    ctx = pr.ProbeContext(authorization={"id": "AP-1", "case_id": case.case_id, "expires_at": iso(T0 + timedelta(hours=1)), "operations": AUTH_OPS}, pmtu_protocols=("icmp",), **CTX_KW)
    return deps(runner, case, ctx=ctx, **kw)


def auth_(case):
    return {"id": "AP-1", "case_id": case.case_id, "expires_at": iso(T0 + timedelta(hours=1)), "operations": AUTH_OPS}


class RuntimeTests(TestCase):
    def _run(self, key, doc, **kw):
        case = make_case(key)
        r = Runner(doc)
        go(case, pm_deps(r, case, **kw))
        return case, r

    def test_PMTUSRC_017_runtime_maps_pmtu_and_hc21_consumes_the_typed_value(self):
        case, r = self._run("pm17", pmtu_doc())
        self.assertIn("pmtu_probe", [c["op"] for c in r.calls])
        o = m.TsObservation.objects.get(case=case, target="h1", key="path.pmtu@h2")
        self.assertEqual((o.value["max_ok_size"], o.value["max_ok_packet"], o.is_missing_data), (1472, 1500, False))
        self.assertEqual(tests_of(case)["HC21"].verdict, "PASS")

    def test_PMTUSRC_018_confirmed_black_hole_only_with_observable_ptb(self):
        case, _ = self._run("pm18", pmtu_doc(limit=1400, vis="observable"))
        self.assertEqual(tests_of(case)["HC21"].verdict, "FAIL")
        case, _ = self._run("pm18b", pmtu_doc(limit=1400, vis="unknown"))
        self.assertEqual(tests_of(case)["HC21"].verdict, "INCONCLUSIVE")
        case, _ = self._run("pm18c", pmtu_doc(limit=1400, vis="unknown", ptb=True))
        hc = tests_of(case)["HC21"]
        self.assertEqual(hc.verdict, "FAIL")                      # a real path-MTU limit, but PMTUD signalling demonstrably works
        self.assertNotIn("black hole", hc.observed_summary.lower())
        self.assertEqual(hc.observed["assessment"]["state"], "LIMIT")

    def test_PMTUSRC_019_missing_large_trials_make_hc21_inconclusive_never_pass(self):
        case, _ = self._run("pm19", pmtu_doc(skip=(1400, 1472)))
        self.assertEqual(tests_of(case)["HC21"].verdict, "INCONCLUSIVE")

    def test_PMTUSRC_020_absent_runner_or_missing_pmtu_authorization_sends_nothing_and_is_unknown(self):
        case = make_case("pm20a")
        go(case, deps(None, case, ctx=pr.ProbeContext(authorization=auth_(case), pmtu_protocols=("icmp",), **CTX_KW)))
        gaps = m.TsObservation.objects.filter(case=case, target="h1", key="path.pmtu@h2", is_missing_data=True)
        self.assertEqual(gaps.count(), 1)
        self.assertTrue(gaps[0].missing_reason.startswith("NOT_CONFIGURED"))
        self.assertIn(tests_of(case)["HC21"].verdict, ("INCONCLUSIVE", "UNAVAILABLE"))
        case = make_case("pm20b")
        r = Runner()
        go(case, deps(r, case, ctx=pr.ProbeContext(authorization={**auth_(case), "operations": []}, pmtu_protocols=("icmp",), **CTX_KW)))      # generic authorization without "pmtu_probe"
        self.assertNotIn("pmtu_probe", [c["op"] for c in r.calls])
        g = m.TsObservation.objects.get(case=case, target="h1", key="path.pmtu@h2")
        self.assertTrue(g.is_missing_data and g.missing_reason.startswith("PERMISSION_DENIED"))
        self.assertIn(tests_of(case)["HC21"].verdict, ("INCONCLUSIVE", "UNAVAILABLE"))

    def test_PMTUSRC_021_restart_with_same_run_key_does_not_resend_size_probes(self):
        case, r = self._run("pm21", pmtu_doc())
        n = len(r.calls)
        go(case, pm_deps(r, case))
        self.assertEqual(len(r.calls), n)

    def test_PMTUSRC_022_only_the_flow_source_sends_and_every_wire_request_is_scoped(self):
        case, r = self._run("pm22", pmtu_doc())
        for c in r.calls:
            self.assertEqual(c["source"]["device"], "h1")
            if c["op"] == "pmtu_probe":
                self.assertEqual((c["destination"]["address"], c["flow"]["dst"], c["df"], c["max_packets"] <= 50, c["authorization_id"]), (ADDR["h2"], "h2", True, True, "AP-1"))


class RunbookTests(SimpleTestCase):
    """MT03/MT05 over typed values (direct runbook calls through the engine fixtures)."""

    def test_PMTUSRC_023_mt03_verdicts_follow_the_assessment(self):
        from core.services.troubleshooting.runbooks import rb06_mtu as rb
        v_ok = obs(run(Runner()))["value"]
        v_unk = obs(run(Runner(pmtu_doc(skip=(1472,)))))["value"]
        v_loss = obs(run(Runner(pmtu_doc(limit=1400, vis="unknown"))))["value"]
        v_bh = obs(run(Runner(pmtu_doc(limit=1400, vis="observable"))))["value"]

        class O:
            def __init__(s, value):
                s.value = value

        class Ctx:
            flow = {"payload_bytes": 1472}
            src, dst = "h1", "h2"

            def __init__(s, value):
                s.v = value

            def need(s, *a):
                return O(s.v)
        got = {n: rb.mt03(Ctx(v)) for n, v in (("ok", v_ok), ("unk", v_unk), ("loss", v_loss), ("bh", v_bh))}
        self.assertEqual({k: r.verdict for k, r in got.items()}, {"ok": "PASS", "unk": "INCONCLUSIVE", "loss": "FAIL", "bh": "FAIL"})
        self.assertLess(got["loss"].finding.confidence, got["bh"].finding.confidence)
        self.assertIn("NOT confirmed", got["loss"].summary)

    def test_PMTUSRC_024_mt05_uses_no_mss_verdict_when_nothing_passed(self):
        from core.services.troubleshooting.runbooks import rb06_mtu as rb
        v = obs(run(Runner(pmtu_doc(limit=100, vis="unknown"))))["value"]
        self.assertIsNone(v["max_ok_size"])

        class O:
            def __init__(s, value):
                s.value = value

        class Ctx:
            src, dst, flow = "h1", "h2", {"name": "web"}

            def need(s, *a):
                return O({"negotiated_mss": 1460})

            def opt(s, *a):
                return O(v)
        res = rb.mt05(Ctx())
        self.assertEqual(res.verdict, "PASS")                      # no MSS verdict is invented from a probe where nothing passed
        self.assertIn("limit None", res.summary)
